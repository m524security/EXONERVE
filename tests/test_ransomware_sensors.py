#!/usr/bin/env python3
"""
Tests for the v3.8 ransomware sensor pack.

These tests exist to prove two things an external reviewer specifically
challenged:

  1. The new detectors actually FIRE on ransomware behaviour (previously
     cloud_exfil and ransomware_esxi had no live emitter at all — only the
     replay harness injected them).
  2. They stay SILENT on the benign workload that used to trip the old
     absolute-entropy logic (a backup job rewriting compressed archives).

Every assertion below maps to a review finding.
"""

import os
import sys
import time
import json
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "guest_production_vm"))

from ransomware_sensors import (  # noqa: E402
    BaselineStore, EntropyTransitionTracker, ExtensionRenameDetector,
    EsxiEncryptionDetector, SlowBurnDetector, EgressVolumeMonitor,
)
from common.siem_export import (  # noqa: E402
    SiemExporter, to_cef, to_ecs_json, to_syslog,
)


class Collector:
    """Captures sensor emissions so tests can assert on them."""

    def __init__(self):
        self.events = []

    def __call__(self, event_type, severity, details):
        self.events.append({"event_type": event_type,
                            "severity": severity, "details": details})

    def types(self):
        return [e["event_type"] for e in self.events]


# ---------------------------------------------------------------------------
# Review finding #4 — compressed-file false positives
# ---------------------------------------------------------------------------

class TestEntropyTransition:
    def test_backup_rewriting_archive_is_not_flagged(self):
        """THE false-positive fix: .tar.gz stays high-entropy across writes.

        Under the old absolute-threshold logic this scored +50 and could
        trigger an instant NIC block on a backup server.
        """
        t = EntropyTransitionTracker()
        path = "/srv/backup/nightly.tar.gz"
        t.classify(path, 7.95)                       # first write, learns prior
        suspicious, reason = t.classify(path, 7.97)  # backup rewrites it
        assert suspicious is False
        assert reason == "already_high_entropy_before_write"

    def test_document_encrypted_in_place_is_flagged(self):
        """No blind spot: encrypting a .docx in place is still caught, even
        though .docx is on the natively-high-entropy list."""
        t = EntropyTransitionTracker()
        path = "/home/user/report.docx"
        t.classify(path, 4.2)                        # ordinary document
        suspicious, reason = t.classify(path, 7.99)  # ransomware encrypts it
        assert suspicious is True
        assert reason == "plaintext_to_ciphertext_transition"

    def test_first_sight_compressed_file_not_flagged(self):
        t = EntropyTransitionTracker()
        suspicious, reason = t.classify("/data/archive.zip", 7.98)
        assert suspicious is False
        assert reason == "first_sight_natively_high_entropy"

    def test_first_sight_unexpected_high_entropy_is_flagged(self):
        t = EntropyTransitionTracker()
        suspicious, reason = t.classify("/home/user/notes.txt", 7.99)
        assert suspicious is True
        assert reason == "first_sight_unexpected_high_entropy"

    def test_low_entropy_never_flagged(self):
        t = EntropyTransitionTracker()
        suspicious, _ = t.classify("/home/user/notes.txt", 3.1)
        assert suspicious is False


# ---------------------------------------------------------------------------
# Review finding #3 — mass extension rename was not watched at all
# ---------------------------------------------------------------------------

class TestExtensionRename:
    def test_mass_locked_extension_fires(self):
        c = Collector()
        d = ExtensionRenameDetector(c, min_files=12)
        for i in range(15):
            d.record_new_file(f"/home/user/doc{i}.locked")
        assert d.evaluate() is not None
        assert "ext_rename" in c.types()
        assert c.events[0]["details"]["extension"] == ".locked"
        assert c.events[0]["details"]["file_count"] == 15

    def test_normal_extensions_do_not_fire(self):
        """A developer creating 50 .py files must not trigger containment."""
        c = Collector()
        d = ExtensionRenameDetector(c, min_files=12)
        for i in range(50):
            d.record_new_file(f"/src/module{i}.py")
        assert d.evaluate() is None
        assert c.events == []

    def test_below_threshold_does_not_fire(self):
        c = Collector()
        d = ExtensionRenameDetector(c, min_files=12)
        for i in range(5):
            d.record_new_file(f"/home/user/doc{i}.wncry")
        assert d.evaluate() is None

    def test_window_expiry_drops_stale_files(self):
        c = Collector()
        d = ExtensionRenameDetector(c, window=1, min_files=12)
        for i in range(15):
            d.record_new_file(f"/home/user/doc{i}.crypt")
        time.sleep(1.1)
        assert d.evaluate() is None


# ---------------------------------------------------------------------------
# Review finding #2 — ransomware_esxi had no live emitter
# ---------------------------------------------------------------------------

class TestEsxiDetector:
    def test_vmdk_mass_encryption_fires(self):
        c = Collector()
        d = EsxiEncryptionDetector(c, min_files=3)
        for i in range(4):
            d.record(f"/vmfs/volumes/ds1/vm{i}/vm{i}.vmdk", 7.99, True)
        assert d.evaluate() is not None
        assert "ransomware_esxi" in c.types()
        assert c.events[0]["details"]["reason"] == "vmdk_mass_encrypt"

    def test_non_vm_files_ignored(self):
        c = Collector()
        d = EsxiEncryptionDetector(c, min_files=3)
        for i in range(10):
            d.record(f"/home/user/file{i}.txt", 7.99, True)
        assert d.evaluate() is None

    def test_benign_vmdk_write_ignored(self):
        """A VM disk written without an entropy transition is normal I/O."""
        c = Collector()
        d = EsxiEncryptionDetector(c, min_files=3)
        for i in range(10):
            d.record(f"/vmfs/volumes/ds1/vm{i}.vmdk", 7.99, False)
        assert d.evaluate() is None


# ---------------------------------------------------------------------------
# Review finding #5 — throttled ransomware evades the 3-sigma burst test
# ---------------------------------------------------------------------------

class TestSlowBurn:
    def test_slow_encryption_fires_without_any_burst(self):
        c = Collector()
        d = SlowBurnDetector(c, min_transitions=150)
        for _ in range(160):
            d.record_transition()
        assert d.evaluate() is not None
        assert "slow_encrypt" in c.types()
        assert c.events[0]["details"]["transitions"] == 160

    def test_normal_activity_does_not_fire(self):
        c = Collector()
        d = SlowBurnDetector(c, min_transitions=150)
        for _ in range(20):
            d.record_transition()
        assert d.evaluate() is None


# ---------------------------------------------------------------------------
# Review finding #1 — cloud_exfil had no live emitter; name-matching evadable
# ---------------------------------------------------------------------------

class TestEgressVolume:
    def test_bulk_egress_fires_on_volume_alone(self):
        """Volume is the signal — no process-name match required, so renaming
        the rclone binary does not evade it."""
        c = Collector()
        m = EgressVolumeMonitor(c, window=300, bytes_threshold=500 * 1024 * 1024)
        now = time.time()
        base = 1_000_000
        m._samples.append((now - 200, base))
        m._samples.append((now - 100, base + 300 * 1024 * 1024))
        m._samples.append((now, base + 900 * 1024 * 1024))
        assert m.evaluate() is not None
        assert "cloud_exfil" in c.types()
        d = c.events[0]["details"]
        assert d["reason"] == "bulk_egress_volume"
        assert d["attribution"] == "correlational"   # honesty about the limit
        assert d["megabytes_out"] >= 500

    def test_normal_traffic_does_not_fire(self):
        c = Collector()
        m = EgressVolumeMonitor(c, window=300, bytes_threshold=500 * 1024 * 1024)
        now = time.time()
        m._samples.append((now - 200, 1_000_000))
        m._samples.append((now - 100, 2_000_000))
        m._samples.append((now, 3_000_000))
        assert m.evaluate() is None

    def test_counter_reset_is_handled(self):
        """Interface flap / reboot resets the kernel counter — must not
        produce a bogus negative-delta alert."""
        c = Collector()
        m = EgressVolumeMonitor(c, window=300)
        now = time.time()
        m._samples.append((now - 200, 900_000_000))
        m._samples.append((now - 100, 5_000))
        m._samples.append((now, 10_000))
        assert m.evaluate() is None
        assert c.events == []

    def test_insufficient_samples_does_not_fire(self):
        c = Collector()
        m = EgressVolumeMonitor(c, window=300, bytes_threshold=1)
        m._samples.append((time.time(), 1_000_000))
        assert m.evaluate() is None


# ---------------------------------------------------------------------------
# Review finding #6 — baselines reset on every restart
# ---------------------------------------------------------------------------

class TestBaselinePersistence:
    def test_state_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            s1 = BaselineStore(path)
            s1.set("slowburn_transitions", [1.0, 2.0, 3.0])
            assert s1.save() is True

            s2 = BaselineStore(path)          # simulates agent restart
            assert s2.get("slowburn_transitions") == [1.0, 2.0, 3.0]

    def test_entropy_priors_survive_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            store = BaselineStore(path)
            t1 = EntropyTransitionTracker(store)
            t1.classify("/srv/backup/a.tar.gz", 7.9)
            t1.persist()
            store.save()

            store2 = BaselineStore(path)
            t2 = EntropyTransitionTracker(store2)
            # Prior survived, so the next write is correctly seen as benign.
            suspicious, reason = t2.classify("/srv/backup/a.tar.gz", 7.95)
            assert suspicious is False
            assert reason == "already_high_entropy_before_write"

    def test_corrupt_state_degrades_to_cold_start(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.json")
            with open(path, "w") as fh:
                fh.write("{not valid json")
            store = BaselineStore(path)       # must not raise
            assert store.get("anything") is None


# ---------------------------------------------------------------------------
# Review finding #7 — no SIEM output
# ---------------------------------------------------------------------------

SAMPLE_EVENT = {
    "vm_id": "web-01",
    "event_type": "crypto_spike",
    "severity": "critical",
    "score": 50,
    "verdict": "CONTAIN",
    "timestamp": "2026-07-19T10:00:00+00:00",
    "timestamp_epoch": 1784455200.0,
    "techniques": [{"id": "T1486", "name": "Data Encrypted for Impact"}],
    "title": "ransomware_crypto_spike",
    "details": {"reason": "ransomware_crypto_spike", "message": "Crypto spike detected",
                "sigma_above_baseline": 6.2},
}


class TestSiemExport:
    def test_cef_render(self):
        line = to_cef(SAMPLE_EVENT)
        assert line.startswith("CEF:0|Exonerve|Exonerve|")
        assert "crypto_spike" in line
        assert "T1486" in line
        assert "|10|" in line          # critical -> CEF severity 10

    def test_ecs_json_render(self):
        doc = json.loads(to_ecs_json(SAMPLE_EVENT))
        assert doc["@timestamp"] == "2026-07-19T10:00:00+00:00"
        assert doc["event"]["kind"] == "alert"
        assert doc["host"]["name"] == "web-01"
        assert doc["threat"]["technique"][0]["id"] == "T1486"
        assert doc["exonerve"]["verdict"] == "CONTAIN"

    def test_syslog_render_rfc5424(self):
        line = to_syslog(SAMPLE_EVENT, hostname="exonerve-ctl")
        assert line.startswith("<106>1 ")      # facility 13, severity 2
        assert "exonerve" in line
        assert 'vm="web-01"' in line

    def test_exporter_writes_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "siem.log")
            ex = SiemExporter(fmt="ecs", file_path=path)
            assert ex.emit(SAMPLE_EVENT) is True
            assert ex.stats["emitted"] == 1
            with open(path) as fh:
                assert json.loads(fh.read().strip())["host"]["name"] == "web-01"

    def test_exporter_never_raises_on_bad_path(self):
        """Export failure must never break detection."""
        ex = SiemExporter(fmt="cef", file_path="/proc/nonexistent/dir/x.log")
        assert ex.emit(SAMPLE_EVENT) is False
        assert ex.stats["file_errors"] == 1

    def test_cef_escaping(self):
        evt = dict(SAMPLE_EVENT)
        evt["details"] = {"reason": "a=b", "message": "line1\nline2"}
        line = to_cef(evt)
        assert "\\=" in line
        assert "\n" not in line

    def test_invalid_format_rejected(self):
        with pytest.raises(ValueError):
            SiemExporter(fmt="not-a-format", file_path="/tmp/x")


# ---------------------------------------------------------------------------
# Control-plane wiring: new event types must be scored and mapped
# ---------------------------------------------------------------------------

class TestControlPlaneWiring:
    def test_new_event_types_have_scores(self):
        sys.path.insert(0, os.path.join(ROOT, "host_control_plane"))
        import control_center
        for et in ("ext_rename", "slow_encrypt", "cloud_exfil", "ransomware_esxi"):
            assert control_center.SCORE_WEIGHTS.get(et, 0) > 0, f"{et} unscored"

    def test_new_event_types_map_to_attack(self):
        from common.mitre_attack import map_event_to_techniques
        for et in ("ext_rename", "slow_encrypt"):
            techs = map_event_to_techniques(et, {})
            assert techs, f"{et} has no ATT&CK mapping"
            assert any(t.tid == "T1486" for t in techs)
