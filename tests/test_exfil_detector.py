#!/usr/bin/env python3
"""
Tests for guest_production_vm/exfil_detector.py (v3.12) — both directions
for each mode, per this project's standing rule.
"""

import os
import sys
import time
import tempfile
import shutil

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "guest_production_vm"))

from exfil_detector import (  # noqa: E402
    ExfilGraphDetector, HoneytokenManager, HoneytokenDetector,
)
from kernel_telemetry import KernelProcessEvent  # noqa: E402


class Collector:
    def __init__(self):
        self.events = []

    def __call__(self, event_type, severity, details):
        self.events.append({"event_type": event_type, "severity": severity,
                            "details": details})

    def types(self):
        return [e["event_type"] for e in self.events]


# ---------------------------------------------------------------------------
# Passive mode — access-then-egress correlation
# ---------------------------------------------------------------------------

class TestPassiveExfilGraph:
    def test_sensitive_access_then_new_destination_fires(self):
        c = Collector()
        d = ExfilGraphDetector(c)
        now = time.time()
        d.record_file_access(1234, "/data/customer_database_backup.csv", now)
        result = d.evaluate_connection(1234, "python3", "203.0.113.9", now + 10)
        assert result is not None
        assert "exfil_graph" in c.types()

    def test_non_sensitive_access_then_connection_does_not_fire(self):
        """Reading an ordinary file then making a connection is completely
        normal (every browser, every package manager) — must stay silent."""
        c = Collector()
        d = ExfilGraphDetector(c)
        now = time.time()
        d.record_file_access(1234, "/home/user/notes.txt", now)
        result = d.evaluate_connection(1234, "python3", "203.0.113.9", now + 10)
        assert result is None
        assert c.events == []

    def test_sensitive_access_then_KNOWN_destination_does_not_fire(self):
        """A process's routine, already-seen destination isn't a signal —
        only egress to something NEW after sensitive access is."""
        c = Collector()
        d = ExfilGraphDetector(c)
        now = time.time()
        # establish 203.0.113.9 as a known destination BEFORE any sensitive access
        d.evaluate_connection(1234, "backup-agent", "203.0.113.9", now)
        d.record_file_access(1234, "/data/customer_database_backup.csv", now + 1)
        result = d.evaluate_connection(1234, "backup-agent", "203.0.113.9", now + 5)
        assert result is None

    def test_sensitive_access_outside_the_correlation_window_does_not_fire(self):
        c = Collector()
        d = ExfilGraphDetector(c, access_window_s=60.0)
        now = time.time()
        d.record_file_access(1234, "/data/passwords_export.xlsx", now)
        result = d.evaluate_connection(1234, "python3", "203.0.113.9", now + 120)
        assert result is None

    def test_different_process_pid_is_not_conflated(self):
        """Process A's sensitive access must not be attributed to process
        B's unrelated connection just because they're both running."""
        c = Collector()
        d = ExfilGraphDetector(c)
        now = time.time()
        d.record_file_access(1111, "/data/customer_database_backup.csv", now)
        result = d.evaluate_connection(2222, "chrome", "203.0.113.9", now + 5)
        assert result is None

    def test_dedupe_window_prevents_repeat_firing_for_same_pid(self):
        c = Collector()
        d = ExfilGraphDetector(c, dedupe_window=600.0)
        now = time.time()
        d.record_file_access(1234, "/data/passwords_export.xlsx", now)
        d.evaluate_connection(1234, "python3", "203.0.113.9", now + 5)
        d.record_file_access(1234, "/data/passwords_export.xlsx", now + 10)
        second = d.evaluate_connection(1234, "python3", "198.51.100.5", now + 15)
        assert second is None   # same pid, still within dedupe window
        assert c.types().count("exfil_graph") == 1

    def test_kernel_event_bridge_feeds_the_same_tracking(self):
        """kernel_telemetry.py events (auditd/Sysmon) must feed the exact
        same access-tracking psutil-sourced calls do — same detector,
        richer source."""
        c = Collector()
        d = ExfilGraphDetector(c)
        now = time.time()
        evt = KernelProcessEvent(
            source="auditd", pid=1234, ppid=1, comm="bash", exe="/bin/bash",
            cmdline=None, uid="0", timestamp=str(now),
            paths=["/data/aws_credentials.bak"])
        d.record_kernel_event(evt)
        result = d.evaluate_connection(1234, "bash", "203.0.113.9", now + 5)
        assert result is not None


# ---------------------------------------------------------------------------
# Active mode — honeytoken files
# ---------------------------------------------------------------------------

class TestHoneytokenManager:
    @pytest.fixture
    def tmp_dir(self):
        d = tempfile.mkdtemp(prefix="exonerve_honeytoken_")
        yield d
        shutil.rmtree(d, ignore_errors=True)

    def test_plant_creates_all_lure_files(self, tmp_dir):
        mgr = HoneytokenManager(tmp_dir)
        planted = mgr.plant()
        assert len(planted) == len(mgr.lure_names)
        for p in planted:
            assert os.path.isfile(p)

    def test_plant_is_idempotent(self, tmp_dir):
        mgr = HoneytokenManager(tmp_dir)
        mgr.plant()
        first_mtime = os.path.getmtime(mgr.planted_paths[0])
        mgr.plant()
        assert os.path.getmtime(mgr.planted_paths[0]) == first_mtime

    def test_auditctl_commands_reference_planted_paths(self, tmp_dir):
        mgr = HoneytokenManager(tmp_dir)
        mgr.plant()
        commands = mgr.auditctl_watch_commands()
        assert len(commands) == len(mgr.planted_paths)
        assert all("auditctl -w" in c and "-p r" in c for c in commands)
        assert all(p in " ".join(commands) for p in mgr.planted_paths)

    def test_access_to_honeytoken_is_flagged(self, tmp_dir):
        mgr = HoneytokenManager(tmp_dir)
        mgr.plant()
        target = mgr.planted_paths[0]
        evt = KernelProcessEvent(source="auditd", pid=999, ppid=1, comm="cat",
                                 exe="/bin/cat", cmdline=f"cat {target}",
                                 uid="1000", timestamp="t", paths=[target])
        findings = mgr.check_kernel_events([evt])
        assert len(findings) == 1
        assert findings[0]["reason"] == "honeytoken_accessed"

    def test_access_to_an_ordinary_file_is_not_flagged(self, tmp_dir):
        """The whole point of a honeytoken is near-zero FP — an unrelated
        legitimate file access must never be mistaken for one."""
        mgr = HoneytokenManager(tmp_dir)
        mgr.plant()
        evt = KernelProcessEvent(source="auditd", pid=1, ppid=1, comm="bash",
                                 exe="/bin/bash", cmdline=None, uid="0",
                                 timestamp="t", paths=["/etc/hostname"])
        assert mgr.check_kernel_events([evt]) == []

    def test_planted_content_never_self_identifies_as_bait(self, tmp_dir):
        """Regression test for a real gap found and fixed the same day it
        shipped: an earlier version wrote 'DECOY FILE — planted by
        Exonerve' literally inside the file, which an attacker reading
        content before exfiltrating would spot instantly and avoid,
        defeating the whole mechanism. Content must look plausible with no
        marker anywhere — the bait status lives only in planted_paths."""
        mgr = HoneytokenManager(tmp_dir)
        mgr.plant()
        giveaway_terms = ("decoy", "bait", "honeytoken", "exonerve", "planted",
                         "trap", "fake", "logged", "monitored", "security control")
        for path in mgr.planted_paths:
            with open(path, encoding="utf-8") as f:
                content = f.read().lower()
            for term in giveaway_terms:
                assert term not in content, (
                    f"{path} contains giveaway term '{term}' — this would "
                    f"tip off an attacker who reads before exfiltrating")

    def test_no_findings_before_planting(self, tmp_dir):
        mgr = HoneytokenManager(tmp_dir)
        evt = KernelProcessEvent(source="auditd", pid=1, ppid=1, comm="cat",
                                 exe="/bin/cat", cmdline=None, uid="0",
                                 timestamp="t", paths=["/data/passwords_export.xlsx"])
        assert mgr.check_kernel_events([evt]) == []


class TestHoneytokenDetectorEmission:
    @pytest.fixture
    def tmp_dir(self):
        d = tempfile.mkdtemp(prefix="exonerve_honeytoken_")
        yield d
        shutil.rmtree(d, ignore_errors=True)

    def test_emits_through_the_standard_sensor_interface(self, tmp_dir):
        c = Collector()
        mgr = HoneytokenManager(tmp_dir)
        mgr.plant()
        detector = HoneytokenDetector(c, mgr)
        target = mgr.planted_paths[0]
        evt = KernelProcessEvent(source="auditd", pid=42, ppid=1, comm="python3",
                                 exe="/usr/bin/python3", cmdline=None, uid="1000",
                                 timestamp="t", paths=[target])
        detector.scan([evt])
        assert c.types() == ["honeytoken_accessed"]

    def test_dedupe_prevents_repeat_page_for_the_same_access(self, tmp_dir):
        c = Collector()
        mgr = HoneytokenManager(tmp_dir)
        mgr.plant()
        detector = HoneytokenDetector(c, mgr, dedupe_window=600.0)
        target = mgr.planted_paths[0]
        evt = KernelProcessEvent(source="auditd", pid=42, ppid=1, comm="python3",
                                 exe="/usr/bin/python3", cmdline=None, uid="1000",
                                 timestamp="t", paths=[target])
        detector.scan([evt])
        detector.scan([evt])
        assert len(c.events) == 1

    def test_clean_scan_emits_nothing(self, tmp_dir):
        c = Collector()
        mgr = HoneytokenManager(tmp_dir)
        mgr.plant()
        detector = HoneytokenDetector(c, mgr)
        evt = KernelProcessEvent(source="auditd", pid=1, ppid=1, comm="bash",
                                 exe="/bin/bash", cmdline=None, uid="0",
                                 timestamp="t", paths=["/etc/hostname"])
        detector.scan([evt])
        assert c.events == []
