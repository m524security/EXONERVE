#!/usr/bin/env python3
"""Tests for host_control_plane/playbook.py (v3.12)."""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "host_control_plane"))

from playbook import Playbook, PlaybookStage  # noqa: E402
from incident_manager import IncidentManager, IncidentStatus  # noqa: E402
from backdoor_check import BackdoorCheck, BackdoorSnapshot  # noqa: E402


class FakeAlert:
    def __init__(self, alert_id, vm_id, severity="critical", techniques=None):
        self.alert_id = alert_id
        self.vm_id = vm_id
        self.severity = severity
        self.techniques = techniques or [{"id": "T1486"}]


def _new_playbook(**kwargs):
    im = IncidentManager()
    incident = im.ingest_alert(FakeAlert("A1", "vm-1"))
    pb = Playbook(incident.incident_id, "vm-1", im, **kwargs)
    return pb, im, incident


class TestHappyPathTraversal:
    def test_full_traversal_reaches_closed(self):
        pb, im, incident = _new_playbook(
            isolate_fn=lambda: {"ok": True, "message": "isolated"},
            mitigate_fn=lambda: {"ok": True, "message": "mitigated"},
            remediate_fn=lambda: {"ok": True, "message": "patched"},
            health_check_fn=lambda: {"healthy": True, "message": "all services up"},
        )
        pb.advance_auto()   # DETECTED -> ISOLATED
        assert pb.stage == PlaybookStage.ISOLATED
        pb.advance_auto()   # ISOLATED -> MITIGATED
        assert pb.stage == PlaybookStage.MITIGATED
        pb.advance_auto()   # MITIGATED -> VULN_SCAN_PENDING
        assert pb.stage == PlaybookStage.VULN_SCAN_PENDING

        result = pb.trigger_vuln_scan([{"cve": "CVE-2026-0001", "severity": "high"}])
        assert result["ok"] and pb.stage == PlaybookStage.VULN_SCAN_COMPLETE

        pb.advance_auto()   # -> REMEDIATION_PENDING
        assert pb.stage == PlaybookStage.REMEDIATION_PENDING

        result = pb.approve_remediation(by="alice")
        assert result["ok"] and pb.stage == PlaybookStage.REMEDIATED

        pb.advance_auto()   # runs backdoor scan -> BACKDOOR_CHECK_PENDING
        assert pb.stage == PlaybookStage.BACKDOOR_CHECK_PENDING

        result = pb.approve_backdoor_check(by="alice", note="clean")
        assert result["ok"] and pb.stage == PlaybookStage.BACKDOOR_CHECK_COMPLETE

        pb.advance_auto()   # -> REVALIDATION_PENDING
        assert pb.stage == PlaybookStage.REVALIDATION_PENDING

        result = pb.complete_revalidation([])
        assert result["ok"] and pb.stage == PlaybookStage.REVALIDATED

        pb.advance_auto()   # -> RECOVERY_CHECKING, health check passes immediately
        assert pb.stage == PlaybookStage.RECOVERED

        result = pb.close(by="alice", note="all clear")
        assert result["ok"] and pb.stage == PlaybookStage.CLOSED
        assert im.get_incident(incident.incident_id).status == IncidentStatus.CLOSED

    def test_isolate_and_mitigate_drive_the_underlying_incident_status(self):
        pb, im, incident = _new_playbook(
            isolate_fn=lambda: {"ok": True}, mitigate_fn=lambda: {"ok": True})
        assert im.get_incident(incident.incident_id).status == IncidentStatus.DETECTED
        pb.advance_auto()
        assert im.get_incident(incident.incident_id).status == IncidentStatus.CONTAINED


class TestAutoStagesDoNotSkipPastFailure:
    def test_failed_isolate_does_not_advance(self):
        pb, _, _ = _new_playbook(isolate_fn=lambda: {"ok": False, "message": "hypervisor unreachable"})
        result = pb.advance_auto()
        assert result["ok"] is False
        assert pb.stage == PlaybookStage.DETECTED

    def test_failed_mitigate_does_not_advance(self):
        pb, _, _ = _new_playbook(
            isolate_fn=lambda: {"ok": True},
            mitigate_fn=lambda: {"ok": False, "message": "action failed"})
        pb.advance_auto()   # isolates fine
        result = pb.advance_auto()   # mitigate fails
        assert result["ok"] is False
        assert pb.stage == PlaybookStage.ISOLATED


class TestGatesRejectOutOfOrderActions:
    """Every gated action must reject being called from the wrong stage —
    this is the actual safety property the human-in-the-loop design
    depends on."""

    def test_cannot_approve_remediation_before_vuln_scan(self):
        pb, _, _ = _new_playbook()
        result = pb.approve_remediation()
        assert result["ok"] is False
        assert "REMEDIATION_PENDING" in result["message"]

    def test_cannot_close_before_recovery(self):
        pb, _, _ = _new_playbook()
        result = pb.close()
        assert result["ok"] is False

    def test_cannot_trigger_vuln_scan_twice(self):
        pb, _, _ = _new_playbook(isolate_fn=lambda: {"ok": True},
                                 mitigate_fn=lambda: {"ok": True})
        pb.advance_auto()
        pb.advance_auto()
        pb.advance_auto()
        assert pb.stage == PlaybookStage.VULN_SCAN_PENDING
        pb.trigger_vuln_scan([])
        second = pb.trigger_vuln_scan([{"cve": "should not land"}])
        assert second["ok"] is False
        assert pb.findings["vuln_scan"] == []   # first call recorded empty list, unchanged

    def test_advance_auto_is_a_pure_noop_at_every_gated_stage(self):
        """The core HITL property: advance_auto() must never silently
        push past a stage that needs a human."""
        pb, _, _ = _new_playbook(isolate_fn=lambda: {"ok": True},
                                 mitigate_fn=lambda: {"ok": True})
        pb.advance_auto(); pb.advance_auto(); pb.advance_auto()
        assert pb.stage == PlaybookStage.VULN_SCAN_PENDING
        for _ in range(5):
            result = pb.advance_auto()
            assert pb.stage == PlaybookStage.VULN_SCAN_PENDING
            assert result.get("gated") is True


class TestRecoveryCheckLoops:
    def test_unhealthy_result_stays_in_recovery_checking(self):
        calls = {"n": 0}

        def flaky_health_check():
            calls["n"] += 1
            return {"healthy": False, "message": f"attempt {calls['n']}: service still down"}

        pb, _, _ = _new_playbook(
            isolate_fn=lambda: {"ok": True}, mitigate_fn=lambda: {"ok": True},
            remediate_fn=lambda: {"ok": True}, health_check_fn=flaky_health_check)
        pb.advance_auto()   # DETECTED -> ISOLATED
        pb.advance_auto()   # ISOLATED -> MITIGATED
        pb.advance_auto()   # MITIGATED -> VULN_SCAN_PENDING
        assert pb.stage == PlaybookStage.VULN_SCAN_PENDING
        pb.trigger_vuln_scan([])
        pb.advance_auto()   # VULN_SCAN_COMPLETE -> REMEDIATION_PENDING
        pb.approve_remediation()
        pb.advance_auto()   # REMEDIATED -> BACKDOOR_CHECK_PENDING (scan runs)
        pb.approve_backdoor_check()
        pb.advance_auto()   # BACKDOOR_CHECK_COMPLETE -> REVALIDATION_PENDING
        pb.complete_revalidation([])
        pb.advance_auto()   # REVALIDATED -> RECOVERY_CHECKING, 1st (unhealthy) check
        assert pb.stage == PlaybookStage.RECOVERY_CHECKING
        assert pb.recovery_check_count == 1

        pb.advance_auto()   # 2nd check, still unhealthy
        assert pb.stage == PlaybookStage.RECOVERY_CHECKING
        assert pb.recovery_check_count == 2

    def test_eventually_healthy_advances_to_recovered(self):
        calls = {"n": 0}

        def health_check():
            calls["n"] += 1
            return {"healthy": calls["n"] >= 3, "message": "checking"}

        pb, im, incident = _new_playbook(
            isolate_fn=lambda: {"ok": True}, mitigate_fn=lambda: {"ok": True},
            remediate_fn=lambda: {"ok": True}, health_check_fn=health_check)
        pb.advance_auto(); pb.advance_auto(); pb.advance_auto()   # -> VULN_SCAN_PENDING
        pb.trigger_vuln_scan([])
        pb.advance_auto()   # -> REMEDIATION_PENDING
        pb.approve_remediation()
        pb.advance_auto()   # -> BACKDOOR_CHECK_PENDING
        pb.approve_backdoor_check()
        pb.advance_auto()   # -> REVALIDATION_PENDING
        pb.complete_revalidation([])
        pb.advance_auto()   # -> RECOVERY_CHECKING, 1st, unhealthy
        pb.advance_auto()   # 2nd, unhealthy
        assert pb.stage == PlaybookStage.RECOVERY_CHECKING
        pb.advance_auto()   # 3rd, healthy
        assert pb.stage == PlaybookStage.RECOVERED
        assert im.get_incident(incident.incident_id).status == IncidentStatus.RECOVERED


class TestReopenEscapeHatch:
    def test_reopen_sends_it_back_and_logs_why(self):
        pb, _, _ = _new_playbook(isolate_fn=lambda: {"ok": True},
                                 mitigate_fn=lambda: {"ok": True})
        pb.advance_auto(); pb.advance_auto(); pb.advance_auto()
        pb.trigger_vuln_scan([])
        pb.advance_auto()
        pb.approve_remediation()
        pb.advance_auto()   # -> BACKDOOR_CHECK_PENDING
        result = pb.reopen_to(PlaybookStage.MITIGATED, by="bob",
                              reason="backdoor check found a suspicious cron entry")
        assert result["ok"]
        assert pb.stage == PlaybookStage.MITIGATED
        assert any("reopened_from_backdoor_check_pending_to_mitigated" == h["event"]
                  for h in pb.history)


class TestBackdoorCheckIntegration:
    def test_baseline_and_diff_produce_findings(self, monkeypatch):
        bc = BackdoorCheck()
        snapshots = iter([
            BackdoorSnapshot(timestamp="t0", ssh_keys={"/root/.ssh/authorized_keys": ["keyA"]},
                            cron_entries={}, startup_services=[], running_processes=[]),
            BackdoorSnapshot(timestamp="t1", ssh_keys={"/root/.ssh/authorized_keys": ["keyA", "keyEVIL"]},
                            cron_entries={}, startup_services=[], running_processes=[]),
        ])
        monkeypatch.setattr(bc, "snapshot", lambda: next(snapshots))

        pb, _, _ = _new_playbook(isolate_fn=lambda: {"ok": True},
                                 mitigate_fn=lambda: {"ok": True},
                                 remediate_fn=lambda: {"ok": True},
                                 backdoor_check=bc)
        pb.capture_baseline()
        pb.advance_auto(); pb.advance_auto(); pb.advance_auto()
        pb.trigger_vuln_scan([])
        pb.advance_auto()
        pb.approve_remediation()
        result = pb.advance_auto()   # runs the backdoor scan
        assert pb.stage == PlaybookStage.BACKDOOR_CHECK_PENDING
        assert len(result["findings"]) == 1
        assert result["findings"][0]["entries"] == ["keyEVIL"]

    def test_no_backdoor_check_configured_produces_no_findings_not_an_error(self):
        pb, _, _ = _new_playbook(isolate_fn=lambda: {"ok": True},
                                 mitigate_fn=lambda: {"ok": True},
                                 remediate_fn=lambda: {"ok": True})
        pb.advance_auto(); pb.advance_auto(); pb.advance_auto()
        pb.trigger_vuln_scan([])
        pb.advance_auto()
        pb.approve_remediation()
        result = pb.advance_auto()
        assert result["findings"] == []


class TestSerialization:
    def test_to_dict_shape(self):
        pb, _, _ = _new_playbook()
        d = pb.to_dict()
        for field in ("incident_id", "vm_id", "stage", "is_gated",
                     "recovery_check_count", "findings", "history"):
            assert field in d


class TestMakeDefaultPlaybookFactory:
    """Covers a real bug caught while wiring this up: an earlier draft used
    a destructive hypervisor action (restore_snapshot) as the health check,
    which would have re-triggered real snapshot restores every time the
    control loop polled it. Fixed to use a non-destructive proxy signal
    instead — these tests pin that fix down."""

    class FakeResult:
        def __init__(self, success=True, message="ok"):
            self.success = success
            self.message = message

    class FakeHypervisor:
        def __init__(self):
            self.block_network_calls = 0
            self.restore_snapshot_calls = 0

        def block_network(self, vm_id):
            self.block_network_calls += 1
            return TestMakeDefaultPlaybookFactory.FakeResult(True, f"blocked {vm_id}")

        def restore_snapshot(self, vm_id):
            self.restore_snapshot_calls += 1
            return TestMakeDefaultPlaybookFactory.FakeResult(True, f"restored {vm_id}")

    def test_health_check_never_calls_a_destructive_hypervisor_action(self):
        from playbook import make_default_playbook
        im = IncidentManager()
        incident = im.ingest_alert(FakeAlert("A1", "vm-1"))
        hyp = self.FakeHypervisor()
        pb = make_default_playbook(incident.incident_id, "vm-1", im, hyp,
                                   quiet_period_s=0.0)
        pb.advance_auto(); pb.advance_auto(); pb.advance_auto()
        pb.trigger_vuln_scan([])
        pb.advance_auto()
        pb.approve_remediation()
        pb.advance_auto()
        pb.approve_backdoor_check()
        pb.advance_auto()
        pb.complete_revalidation([])
        pb.advance_auto()   # enters RECOVERY_CHECKING and runs the health check
        assert hyp.restore_snapshot_calls == 0, (
            "health check must never call a destructive/action-triggering "
            "hypervisor method — it should only ever query, never act")

    def test_isolate_and_mitigate_call_block_network(self):
        from playbook import make_default_playbook
        im = IncidentManager()
        incident = im.ingest_alert(FakeAlert("A1", "vm-1"))
        hyp = self.FakeHypervisor()
        pb = make_default_playbook(incident.incident_id, "vm-1", im, hyp)
        pb.advance_auto()   # isolate
        pb.advance_auto()   # mitigate
        assert hyp.block_network_calls == 2

    def test_health_check_fails_immediately_after_fresh_activity(self):
        from playbook import make_default_playbook
        im = IncidentManager()
        incident = im.ingest_alert(FakeAlert("A1", "vm-1"))
        hyp = self.FakeHypervisor()
        pb = make_default_playbook(incident.incident_id, "vm-1", im, hyp,
                                   quiet_period_s=3600.0)   # 1hr quiet period required
        pb.advance_auto(); pb.advance_auto(); pb.advance_auto()
        pb.trigger_vuln_scan([])
        pb.advance_auto()
        pb.approve_remediation()
        pb.advance_auto()
        pb.approve_backdoor_check()
        pb.advance_auto()
        pb.complete_revalidation([])
        pb.advance_auto()   # health check: incident had activity moments ago, quiet_period not met
        assert pb.stage == PlaybookStage.RECOVERY_CHECKING   # not yet RECOVERED
