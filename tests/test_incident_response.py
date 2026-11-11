#!/usr/bin/env python3
"""
Tests for host_control_plane/incident_manager.py and escalation_policy.py
(v3.11 — Incident Response Priorities 1, 3, 4).
"""

import os
import sys
import time
import shutil
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "host_control_plane"))

from incident_manager import (  # noqa: E402
    IncidentManager, IncidentStatus,
)
from escalation_policy import EscalationPolicy  # noqa: E402
from alert_manager import AlertManager, AlertStatus  # noqa: E402


# ---------------------------------------------------------------------------
# Lightweight duck-typed Alert stand-in — IncidentManager only needs
# .alert_id/.vm_id/.severity/.techniques, so unit tests for correlation logic
# don't need a full AlertManager round-trip. Integration-style tests further
# down use the real AlertManager.raise_alert() instead.
# ---------------------------------------------------------------------------

class FakeAlert:
    def __init__(self, alert_id, vm_id, severity="high", techniques=None):
        self.alert_id = alert_id
        self.vm_id = vm_id
        self.severity = severity
        self.techniques = techniques or []


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------

class TestCorrelation:
    def test_two_alerts_same_vm_join_one_incident(self):
        im = IncidentManager()
        a1 = FakeAlert("A1", "vm-1", techniques=[{"id": "T1486"}])
        a2 = FakeAlert("A2", "vm-1", techniques=[{"id": "T1071"}])
        inc1 = im.ingest_alert(a1)
        inc2 = im.ingest_alert(a2)
        assert inc1.incident_id == inc2.incident_id
        assert set(inc1.alert_ids) == {"A1", "A2"}
        assert set(inc1.technique_counts.keys()) == {"T1486", "T1071"}

    def test_different_vms_get_different_incidents(self):
        im = IncidentManager()
        inc1 = im.ingest_alert(FakeAlert("A1", "vm-1"))
        inc2 = im.ingest_alert(FakeAlert("A2", "vm-2"))
        assert inc1.incident_id != inc2.incident_id

    def test_gap_beyond_correlation_window_opens_new_incident(self):
        im = IncidentManager(correlation_window_s=0.2)
        inc1 = im.ingest_alert(FakeAlert("A1", "vm-1"))
        time.sleep(0.3)
        inc2 = im.ingest_alert(FakeAlert("A2", "vm-1"))
        assert inc1.incident_id != inc2.incident_id

    def test_repeated_technique_increments_count_not_a_new_key(self):
        im = IncidentManager()
        im.ingest_alert(FakeAlert("A1", "vm-1", techniques=[{"id": "T1486"}]))
        inc = im.ingest_alert(FakeAlert("A2", "vm-1", techniques=[{"id": "T1486"}]))
        assert inc.technique_counts["T1486"] == 2

    def test_severity_peak_tracks_the_highest_seen_not_the_latest(self):
        im = IncidentManager()
        im.ingest_alert(FakeAlert("A1", "vm-1", severity="critical"))
        inc = im.ingest_alert(FakeAlert("A2", "vm-1", severity="low"))
        assert inc.severity_peak == "critical"

    def test_closed_incident_is_not_silently_reopened(self):
        im = IncidentManager()
        inc1 = im.ingest_alert(FakeAlert("A1", "vm-1"))
        im.transition(inc1.incident_id, IncidentStatus.CONTAINED)
        im.transition(inc1.incident_id, IncidentStatus.RECOVERED)
        im.transition(inc1.incident_id, IncidentStatus.CLOSED)

        inc2 = im.ingest_alert(FakeAlert("A2", "vm-1"))
        assert inc2.incident_id != inc1.incident_id
        assert inc1.incident_id in inc2.linked_incident_ids
        # the closed incident's own alert list must not have been mutated
        assert "A2" not in inc1.alert_ids


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------

class TestLifecycle:
    def test_valid_transition_sequence_succeeds(self):
        im = IncidentManager()
        inc = im.ingest_alert(FakeAlert("A1", "vm-1"))
        for step in (IncidentStatus.TRIAGED, IncidentStatus.CONTAINED,
                    IncidentStatus.RECOVERED, IncidentStatus.CLOSED):
            result = im.transition(inc.incident_id, step)
            assert result["ok"], result["message"]
        assert im.get_incident(inc.incident_id).status == IncidentStatus.CLOSED

    def test_skipping_straight_to_contained_is_allowed(self):
        """A fast-moving ransomware case can jump straight to containment
        without a separate triage step — the lifecycle should not force
        busywork that costs response time."""
        im = IncidentManager()
        inc = im.ingest_alert(FakeAlert("A1", "vm-1"))
        result = im.transition(inc.incident_id, IncidentStatus.CONTAINED)
        assert result["ok"]

    def test_invalid_transition_is_rejected_with_a_clear_reason(self):
        im = IncidentManager()
        inc = im.ingest_alert(FakeAlert("A1", "vm-1"))
        result = im.transition(inc.incident_id, IncidentStatus.RECOVERED)
        assert result["ok"] is False
        assert "DETECTED" in result["message"] and "RECOVERED" in result["message"]

    def test_transitioning_out_of_closed_is_never_allowed(self):
        im = IncidentManager()
        inc = im.ingest_alert(FakeAlert("A1", "vm-1"))
        im.transition(inc.incident_id, IncidentStatus.CLOSED)
        result = im.transition(inc.incident_id, IncidentStatus.DETECTED)
        assert result["ok"] is False

    def test_unknown_incident_id_fails_cleanly(self):
        im = IncidentManager()
        result = im.transition("INC-99999", IncidentStatus.CLOSED)
        assert result["ok"] is False
        assert "not found" in result["message"]

    def test_closing_removes_it_from_open_correlation(self):
        """After close, a NEW alert on the same VM must not attach to the
        closed incident even if it arrives within the correlation window."""
        im = IncidentManager(correlation_window_s=600)
        inc1 = im.ingest_alert(FakeAlert("A1", "vm-1"))
        im.transition(inc1.incident_id, IncidentStatus.CLOSED)
        inc2 = im.ingest_alert(FakeAlert("A2", "vm-1"))
        assert inc2.incident_id != inc1.incident_id


class TestQueries:
    def test_list_incidents_filters_by_status(self):
        im = IncidentManager()
        inc1 = im.ingest_alert(FakeAlert("A1", "vm-1"))
        im.ingest_alert(FakeAlert("A2", "vm-2"))
        im.transition(inc1.incident_id, IncidentStatus.CLOSED)

        open_only = im.list_incidents(status=IncidentStatus.DETECTED)
        assert len(open_only) == 1
        assert open_only[0]["vm_id"] == "vm-2"

    def test_list_incidents_filters_by_vm(self):
        im = IncidentManager()
        im.ingest_alert(FakeAlert("A1", "vm-1"))
        im.ingest_alert(FakeAlert("A2", "vm-2"))
        result = im.list_incidents(vm_id="vm-1")
        assert len(result) == 1 and result[0]["vm_id"] == "vm-1"


# ---------------------------------------------------------------------------
# Post-incident report (Priority 3) — real integration with the existing
# kill-chain/Navigator/STIX tools, not mocks.
# ---------------------------------------------------------------------------

class TestPostIncidentReport:
    @pytest.fixture
    def tmp_out(self):
        d = tempfile.mkdtemp(prefix="exonerve_ir_report_")
        yield d
        shutil.rmtree(d, ignore_errors=True)

    def test_report_generation_produces_all_three_artifacts(self, tmp_out):
        im = IncidentManager()
        im.ingest_alert(FakeAlert("A1", "vm-1", severity="critical",
                                  techniques=[{"id": "T1486"}, {"id": "T1071"}]))
        inc = im.list_incidents()[0]

        result = im.generate_report(inc["incident_id"], tmp_out,
                                    ir_log=[{"timestamp": "2026-01-01T00:00:00Z",
                                            "operation": "isolate_host",
                                            "success": True, "message": "isolated vm-1"}])
        assert os.path.isfile(result["markdown_path"])
        assert os.path.isfile(result["navigator_layer_path"])
        assert os.path.isfile(result["stix_bundle_path"])

    def test_report_content_includes_kill_chain_techniques_and_actions(self, tmp_out):
        im = IncidentManager()
        im.ingest_alert(FakeAlert("A1", "vm-1", techniques=[{"id": "T1486"}]))
        inc = im.list_incidents()[0]
        result = im.generate_report(
            inc["incident_id"], tmp_out,
            ir_log=[{"timestamp": "t", "operation": "isolate_host",
                    "success": True, "message": "done"}])

        with open(result["markdown_path"]) as f:
            content = f.read()
        assert "T1486" in content
        assert "isolate_host" in content
        assert "Kill-chain reconstruction" in content
        assert inc["incident_id"] in content

    def test_report_on_incident_with_no_techniques_does_not_crash(self, tmp_out):
        """An incident correlated purely from behavioural alerts with no
        mapped ATT&CK technique must still produce a report, not error out."""
        im = IncidentManager()
        im.ingest_alert(FakeAlert("A1", "vm-1", techniques=[]))
        inc = im.list_incidents()[0]
        result = im.generate_report(inc["incident_id"], tmp_out)
        assert os.path.isfile(result["markdown_path"])

    def test_unknown_incident_raises_valueerror(self, tmp_out):
        im = IncidentManager()
        with pytest.raises(ValueError):
            im.generate_report("INC-99999", tmp_out)


# ---------------------------------------------------------------------------
# Escalation policy (Priority 4)
# ---------------------------------------------------------------------------

class FakeTicketing:
    def __init__(self, configured=True, fail=False):
        self._configured = configured
        self.fail = fail
        self.emitted = []

    def configured(self):
        return self._configured

    def emit(self, event):
        if self.fail:
            raise ConnectionError("simulated ticketing outage")
        self.emitted.append(event)
        return True


class TestEscalationPolicy:
    def _stale_alert_manager(self, age_s=1000.0):
        am = AlertManager(dedupe_window_s=0.0)
        alert = am.raise_alert("vm-1", "crypto_spike", "critical", 50,
                               {"message": "test"})
        alert.created_ts = time.time() - age_s   # backdate without sleeping
        return am, alert

    def test_unconfigured_ticketing_is_a_pure_noop(self):
        am, _ = self._stale_alert_manager()
        policy = EscalationPolicy(am, FakeTicketing(configured=False), escalate_after_s=1.0)
        assert policy.check_and_escalate() == []

    def test_no_ticketing_at_all_is_a_pure_noop(self):
        am, _ = self._stale_alert_manager()
        policy = EscalationPolicy(am, None, escalate_after_s=1.0)
        assert policy.check_and_escalate() == []

    def test_stale_open_alert_gets_escalated(self):
        am, alert = self._stale_alert_manager(age_s=1000.0)
        ticketing = FakeTicketing()
        policy = EscalationPolicy(am, ticketing, escalate_after_s=900.0)

        escalated = policy.check_and_escalate()
        assert escalated == [alert.alert_id]
        assert len(ticketing.emitted) == 1
        assert "ESCALATED" in ticketing.emitted[0]["title"]
        assert am.get_alerts()[0]["status"] == AlertStatus.ESCALATED.value

    def test_fresh_alert_is_not_escalated_yet(self):
        am, alert = self._stale_alert_manager(age_s=10.0)
        ticketing = FakeTicketing()
        policy = EscalationPolicy(am, ticketing, escalate_after_s=900.0)
        assert policy.check_and_escalate() == []
        assert ticketing.emitted == []

    def test_acknowledged_alert_is_never_escalated(self):
        am, alert = self._stale_alert_manager(age_s=1000.0)
        am.acknowledge(alert.alert_id, by="analyst")
        ticketing = FakeTicketing()
        policy = EscalationPolicy(am, ticketing, escalate_after_s=900.0)
        assert policy.check_and_escalate() == []

    def test_does_not_double_escalate_the_same_alert(self):
        am, alert = self._stale_alert_manager(age_s=1000.0)
        ticketing = FakeTicketing()
        policy = EscalationPolicy(am, ticketing, escalate_after_s=900.0)
        policy.check_and_escalate()
        # alert.status is now ESCALATED, which stale_open_alerts already
        # excludes going forward — but also verify the policy's own memory
        # prevents a double-page even if called again immediately.
        second = policy.check_and_escalate()
        assert second == []
        assert len(ticketing.emitted) == 1

    def test_ticketing_failure_does_not_raise_and_leaves_it_retryable(self):
        am, alert = self._stale_alert_manager(age_s=1000.0)
        ticketing = FakeTicketing(fail=True)
        policy = EscalationPolicy(am, ticketing, escalate_after_s=900.0)
        escalated = policy.check_and_escalate()   # must not raise
        assert escalated == []
        # status must still be OPEN (never flipped) so a later, working
        # ticketing backend can still pick it up
        assert am.get_alerts()[0]["status"] == AlertStatus.OPEN.value


class TestStaleOpenAlertsQuery:
    def test_excludes_alerts_younger_than_threshold(self):
        am = AlertManager(dedupe_window_s=0.0)
        am.raise_alert("vm-1", "crypto_spike", "high", 50, {})
        assert am.stale_open_alerts(older_than_s=3600) == []

    def test_includes_only_open_status(self):
        am = AlertManager(dedupe_window_s=0.0)
        a1 = am.raise_alert("vm-1", "crypto_spike", "high", 50, {})
        a2 = am.raise_alert("vm-2", "beacon", "high", 50, {})
        a1.created_ts = time.time() - 1000
        a2.created_ts = time.time() - 1000
        am.acknowledge(a2.alert_id)
        stale = am.stale_open_alerts(older_than_s=900)
        assert [a.alert_id for a in stale] == [a1.alert_id]
