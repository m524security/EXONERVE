#!/usr/bin/env python3
"""
Integration tests for the /api/incidents* Flask routes added in v3.11.

The existing test suite has zero coverage of the Flask API surface at all
(pre-existing gap, not introduced here) — these tests exist specifically to
prove the new routes are actually reachable and wired correctly end-to-end,
not just correct in isolation. Caught two real bugs before landing: a
nonexistent `engine.get_vm()` call, and a missing IncidentStatus import.
"""

import os
import sys
import shutil

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "host_control_plane"))

import control_center as cc  # noqa: E402
from hypervisor_api import HypervisorAPI, load_default_config, HypervisorResult  # noqa: E402
from failover_orchestrator import FailoverOrchestrator, SimulatedBackend  # noqa: E402


@pytest.fixture
def app_client():
    hyp = HypervisorAPI(load_default_config())
    failover = FailoverOrchestrator(SimulatedBackend())
    engine = cc.CorrelationEngine(hyp, failover)
    app = cc.create_flask_app(engine, api_token="test-token-123")
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client, engine


def _raise_alert(engine, vm_id="vm-1", event_type="crypto_spike",
                 severity="critical", delta=50, techniques=None):
    """Drive an alert through the real path: AlertManager.raise_alert() then
    IncidentManager.ingest_alert(), exactly as control_center.py's telemetry
    handler does — not a shortcut that bypasses the actual wiring."""
    details = {"message": "test event", "attack": techniques or [{"id": "T1486"}]}
    alert = engine.alerts.raise_alert(vm_id, event_type, severity, delta, details)
    if alert:
        engine.incidents.ingest_alert(alert)
    return alert


class TestIncidentListAndDetail:
    def test_list_incidents_empty_initially(self, app_client):
        client, engine = app_client
        resp = client.get("/api/incidents")
        assert resp.status_code == 200
        assert resp.get_json()["incidents"] == []

    def test_list_incidents_after_an_alert(self, app_client):
        client, engine = app_client
        _raise_alert(engine)
        resp = client.get("/api/incidents")
        data = resp.get_json()["incidents"]
        assert len(data) == 1
        assert data[0]["vm_id"] == "vm-1"
        assert data[0]["status"] == "DETECTED"

    def test_incident_detail_by_id(self, app_client):
        client, engine = app_client
        _raise_alert(engine)
        incident_id = engine.incidents.list_incidents()[0]["incident_id"]
        resp = client.get(f"/api/incidents/{incident_id}")
        assert resp.status_code == 200
        assert resp.get_json()["incident_id"] == incident_id

    def test_unknown_incident_detail_is_404(self, app_client):
        client, _ = app_client
        resp = client.get("/api/incidents/INC-99999")
        assert resp.status_code == 404

    def test_status_endpoint_includes_incidents(self, app_client):
        client, engine = app_client
        _raise_alert(engine)
        resp = client.get("/api/status")
        assert "incidents" in resp.get_json()
        assert len(resp.get_json()["incidents"]) == 1


class TestIncidentActionsAreAuthGated:
    """Same posture as /api/alerts/: state-changing incident actions require
    the API token for remote callers, but trust localhost (documented,
    intentional design — "anyone on the box can run commands directly").
    Flask's test client defaults to REMOTE_ADDR=127.0.0.1, so a genuinely
    remote caller has to be simulated explicitly via environ_base to
    actually exercise the token gate rather than hit the localhost bypass."""

    _REMOTE = {"REMOTE_ADDR": "203.0.113.5"}

    def test_localhost_caller_is_trusted_without_a_token(self, app_client):
        """The documented bypass, proven rather than assumed."""
        client, engine = app_client
        _raise_alert(engine)
        incident_id = engine.incidents.list_incidents()[0]["incident_id"]
        resp = client.post(f"/api/incidents/{incident_id}/contained")
        assert resp.status_code == 200

    def test_remote_caller_without_token_is_rejected(self, app_client):
        client, engine = app_client
        _raise_alert(engine)
        incident_id = engine.incidents.list_incidents()[0]["incident_id"]
        resp = client.post(f"/api/incidents/{incident_id}/contained",
                           environ_base=self._REMOTE)
        assert resp.status_code == 401

    def test_remote_caller_with_correct_token_succeeds(self, app_client):
        client, engine = app_client
        _raise_alert(engine)
        incident_id = engine.incidents.list_incidents()[0]["incident_id"]
        resp = client.post(f"/api/incidents/{incident_id}/contained",
                           headers={"X-Exonerve-Token": "test-token-123"},
                           environ_base=self._REMOTE)
        assert resp.status_code == 200
        assert resp.get_json()["ok"] is True
        assert engine.incidents.get_incident(incident_id).status.value == "CONTAINED"

    def test_remote_caller_with_wrong_token_is_rejected(self, app_client):
        client, engine = app_client
        _raise_alert(engine)
        incident_id = engine.incidents.list_incidents()[0]["incident_id"]
        resp = client.post(f"/api/incidents/{incident_id}/contained",
                           headers={"X-Exonerve-Token": "wrong-token"},
                           environ_base=self._REMOTE)
        assert resp.status_code == 401

    def test_invalid_status_name_returns_400_not_500(self, app_client):
        client, engine = app_client
        _raise_alert(engine)
        incident_id = engine.incidents.list_incidents()[0]["incident_id"]
        resp = client.post(f"/api/incidents/{incident_id}/not_a_real_status",
                           headers={"X-Exonerve-Token": "test-token-123"})
        assert resp.status_code == 400


class TestIncidentReportEndpoint:
    def test_report_generation_over_http(self, app_client, tmp_path, monkeypatch):
        client, engine = app_client
        _raise_alert(engine, techniques=[{"id": "T1486"}])
        incident_id = engine.incidents.list_incidents()[0]["incident_id"]

        resp = client.post(f"/api/incidents/{incident_id}/report",
                           headers={"X-Exonerve-Token": "test-token-123"})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["ok"] is True
        assert "# Post-Incident Report" in data["markdown"]
        assert incident_id in data["markdown"]
        assert os.path.isfile(data["navigator_layer_path"])
        assert os.path.isfile(data["stix_bundle_path"])

        # cleanup — this endpoint writes real files under host_control_plane/
        report_dir = os.path.dirname(data["navigator_layer_path"])
        shutil.rmtree(report_dir, ignore_errors=True)

    def test_report_for_unknown_incident_is_404(self, app_client):
        client, _ = app_client
        resp = client.post("/api/incidents/INC-99999/report",
                           headers={"X-Exonerve-Token": "test-token-123"})
        assert resp.status_code == 404


class TestPlaybookAPI:
    _TOKEN = {"X-Exonerve-Token": "test-token-123"}

    def test_playbook_status_lazily_creates_and_returns(self, app_client):
        client, engine = app_client
        _raise_alert(engine)
        incident_id = engine.incidents.list_incidents()[0]["incident_id"]
        resp = client.get(f"/api/incidents/{incident_id}/playbook")
        assert resp.status_code == 200
        assert resp.get_json()["stage"] == "DETECTED"

    def test_playbook_status_for_unknown_incident_is_404(self, app_client):
        client, _ = app_client
        resp = client.get("/api/incidents/INC-99999/playbook")
        assert resp.status_code == 404

    def test_advance_moves_through_isolate_and_mitigate(self, app_client, monkeypatch):
        client, engine = app_client
        _raise_alert(engine)
        incident_id = engine.incidents.list_incidents()[0]["incident_id"]
        # This sandbox has no VBoxManage binary, so the real hypervisor
        # backend's block_network() legitimately fails here — which is
        # exactly why the playbook correctly refuses to advance on a
        # failed isolate (see TestAutoStagesDoNotSkipPastFailure in
        # test_playbook.py). Substituting a working isolate call to test
        # the SUCCESS path specifically, same as substituting any other
        # externally-unavailable dependency elsewhere in this suite.
        monkeypatch.setattr(engine.hypervisor, "block_network",
                            lambda vm_id: HypervisorResult(
                                success=True, operation="block_network",
                                vm_id=vm_id, message="simulated block for test"))
        r1 = client.post(f"/api/incidents/{incident_id}/playbook/advance",
                         headers=self._TOKEN)
        assert r1.status_code == 200
        assert r1.get_json()["ok"] is True
        r2 = client.post(f"/api/incidents/{incident_id}/playbook/advance",
                         headers=self._TOKEN)
        status = client.get(f"/api/incidents/{incident_id}/playbook").get_json()
        assert status["stage"] == "MITIGATED"

    def test_gated_action_out_of_order_returns_ok_false(self, app_client):
        client, engine = app_client
        _raise_alert(engine)
        incident_id = engine.incidents.list_incidents()[0]["incident_id"]
        resp = client.post(f"/api/incidents/{incident_id}/playbook/approve_remediation",
                           headers=self._TOKEN)
        assert resp.status_code == 200   # not an HTTP error — a rejected action
        assert resp.get_json()["ok"] is False

    def test_playbook_actions_are_auth_gated_like_incidents(self, app_client):
        client, engine = app_client
        _raise_alert(engine)
        incident_id = engine.incidents.list_incidents()[0]["incident_id"]
        resp = client.post(f"/api/incidents/{incident_id}/playbook/advance",
                           environ_base={"REMOTE_ADDR": "203.0.113.5"})
        assert resp.status_code == 401

    def test_reopen_with_invalid_stage_name_is_400_not_500(self, app_client):
        client, engine = app_client
        _raise_alert(engine)
        incident_id = engine.incidents.list_incidents()[0]["incident_id"]
        resp = client.post(f"/api/incidents/{incident_id}/playbook/reopen",
                           json={"stage": "NOT_A_REAL_STAGE"}, headers=self._TOKEN)
        assert resp.status_code == 400

    def test_unknown_playbook_action_is_400_not_500(self, app_client):
        client, engine = app_client
        _raise_alert(engine)
        incident_id = engine.incidents.list_incidents()[0]["incident_id"]
        resp = client.post(f"/api/incidents/{incident_id}/playbook/not_a_real_action",
                           headers=self._TOKEN)
        assert resp.status_code == 400
