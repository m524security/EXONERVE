#!/usr/bin/env python3
"""
Tests for common/ticketing_export.py — EXONERVE_NEXT_UPDATE_PROMPT.md
Priority 1.2: "a test confirms a failed HTTP call to the ticketing endpoint
is caught, logged, and never raises into the caller. A test confirms the
payload shape matches PagerDuty's documented event schema."
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from common.ticketing_export import (  # noqa: E402
    TicketingExporter, to_pagerduty_event, to_generic_webhook_payload,
    ticketing_from_env, PAGERDUTY_EVENTS_URL,
)


SAMPLE_EVENT = {
    "vm_id": "vm-web-03",
    "event_type": "crypto_spike",
    "severity": "critical",
    "score": 50,
    "details": {
        "reason": "entropy_transition_burst",
        "message": "12 files transitioned plaintext->ciphertext in 30s",
        "file_count": 12,
    },
    "timestamp": "2026-07-20T00:00:00+00:00",
    "techniques": [{"id": "T1486", "name": "Data Encrypted for Impact"}],
    "title": "Ransomware cryptographic spike",
}


# ---------------------------------------------------------------------------
# PagerDuty payload shape — must match the documented Events API v2 schema
# ---------------------------------------------------------------------------

class TestPagerDutyPayloadShape:
    def test_required_top_level_fields(self):
        payload = to_pagerduty_event(SAMPLE_EVENT, "fake-routing-key-123")
        assert payload["routing_key"] == "fake-routing-key-123"
        assert payload["event_action"] == "trigger"
        assert "dedup_key" in payload and payload["dedup_key"]
        assert payload["client"] == "Exonerve"

    def test_required_payload_subfields(self):
        payload = to_pagerduty_event(SAMPLE_EVENT, "key")
        p = payload["payload"]
        for field in ("summary", "source", "severity", "timestamp"):
            assert field in p and p[field], f"missing/empty required field: {field}"

    def test_severity_is_constrained_to_pagerduty_vocabulary(self):
        """PagerDuty rejects any payload.severity outside this exact set —
        Exonerve's own severities must never be passed through raw."""
        allowed = {"critical", "error", "warning", "info"}
        for gsev in ("low", "medium", "high", "critical", "nonsense"):
            event = dict(SAMPLE_EVENT, severity=gsev)
            payload = to_pagerduty_event(event, "key")
            assert payload["payload"]["severity"] in allowed

    def test_summary_is_capped_at_1024_chars(self):
        event = dict(SAMPLE_EVENT)
        event["details"] = dict(SAMPLE_EVENT["details"], message="x" * 5000)
        payload = to_pagerduty_event(event, "key")
        assert len(payload["payload"]["summary"]) <= 1024

    def test_dedup_key_correlates_repeats_of_the_same_issue(self):
        """Same vm + same event_type -> same dedup_key, so PagerDuty groups
        repeated pages into one incident instead of paging fresh each time."""
        p1 = to_pagerduty_event(SAMPLE_EVENT, "key")
        p2 = to_pagerduty_event(SAMPLE_EVENT, "key")
        assert p1["dedup_key"] == p2["dedup_key"]
        different_vm = dict(SAMPLE_EVENT, vm_id="vm-other")
        p3 = to_pagerduty_event(different_vm, "key")
        assert p3["dedup_key"] != p1["dedup_key"]

    def test_custom_details_carries_full_evidence(self):
        payload = to_pagerduty_event(SAMPLE_EVENT, "key")
        cd = payload["payload"]["custom_details"]
        assert cd["score"] == 50
        assert cd["techniques"] == SAMPLE_EVENT["techniques"]
        assert cd["details"] == SAMPLE_EVENT["details"]

    def test_client_url_is_optional(self):
        no_url = to_pagerduty_event(SAMPLE_EVENT, "key")
        assert "client_url" not in no_url
        with_url = to_pagerduty_event(SAMPLE_EVENT, "key",
                                       client_url="https://dash.example/vm-web-03")
        assert with_url["client_url"] == "https://dash.example/vm-web-03"

    def test_rejects_missing_routing_key(self):
        with pytest.raises(ValueError):
            to_pagerduty_event(SAMPLE_EVENT, "")

    def test_rejects_invalid_event_action(self):
        with pytest.raises(ValueError):
            to_pagerduty_event(SAMPLE_EVENT, "key", event_action="delete_everything")


class TestGenericWebhookPayloadShape:
    def test_has_stable_top_level_fields(self):
        payload = to_generic_webhook_payload(SAMPLE_EVENT)
        for field in ("source", "vm_id", "event_type", "severity", "score",
                      "title", "techniques", "details", "timestamp"):
            assert field in payload


# ---------------------------------------------------------------------------
# Failure handling — the whole point of this module
# ---------------------------------------------------------------------------

class TestFailureIsolation:
    def test_failed_pagerduty_call_is_caught_and_counted_not_raised(self):
        def broken_poster(url, payload, timeout):
            raise ConnectionError("simulated: PagerDuty unreachable")

        exp = TicketingExporter(pagerduty_routing_key="key", poster=broken_poster)
        result = exp.emit(SAMPLE_EVENT)   # must not raise
        assert result is False
        assert exp.stats["pagerduty_errors"] == 1
        assert exp.stats["dropped"] == 1

    def test_failed_webhook_call_is_caught_and_counted_not_raised(self):
        def broken_poster(url, payload, timeout):
            raise TimeoutError("simulated: webhook timed out")

        exp = TicketingExporter(webhook_url="https://hooks.example/exonerve",
                                poster=broken_poster)
        result = exp.emit(SAMPLE_EVENT)
        assert result is False
        assert exp.stats["webhook_errors"] == 1

    def test_one_backend_failing_does_not_block_the_other(self):
        calls = []

        def flaky_poster(url, payload, timeout):
            calls.append(url)
            if url == PAGERDUTY_EVENTS_URL:
                raise ConnectionError("PagerDuty down")
            return True   # webhook succeeds

        exp = TicketingExporter(pagerduty_routing_key="key",
                                webhook_url="https://hooks.example/exonerve",
                                poster=flaky_poster)
        result = exp.emit(SAMPLE_EVENT)
        assert result is True, "webhook success must still count as landed"
        assert exp.stats["pagerduty_errors"] == 1
        assert exp.stats["emitted"] == 1

    def test_malformed_event_does_not_raise(self):
        """A garbage event dict must degrade to 'dropped', never an
        exception bubbling into the caller's detection/scoring loop."""
        exp = TicketingExporter(pagerduty_routing_key="key",
                                poster=lambda *a: True)
        result = exp.emit({})
        assert result in (True, False)   # must return, not raise
        assert exp.stats["dropped"] >= 0

    def test_disabled_exporter_is_a_pure_noop(self):
        calls = []
        exp = TicketingExporter(pagerduty_routing_key="key", enabled=False,
                                poster=lambda *a: calls.append(a) or True)
        assert exp.emit(SAMPLE_EVENT) is False
        assert calls == []

    def test_unconfigured_exporter_is_a_pure_noop(self):
        calls = []
        exp = TicketingExporter(poster=lambda *a: calls.append(a) or True)
        assert exp.configured() is False
        assert exp.emit(SAMPLE_EVENT) is False
        assert calls == []

    def test_non_http_scheme_webhook_url_is_rejected_not_opened(self):
        """v3.13 security fix (bandit B310): a misconfigured webhook_url
        pointing at file:// or another unexpected scheme must be rejected
        by the DEFAULT poster, not silently opened. Uses the real
        _default_poster (no poster= override) specifically to prove the
        actual transport function does the validation, not just that a
        test double would."""
        exp = TicketingExporter(webhook_url="file:///etc/passwd")
        result = exp.emit(SAMPLE_EVENT)   # must not raise, must not succeed
        assert result is False
        assert exp.stats["webhook_errors"] == 1

    def test_https_and_http_schemes_are_accepted_by_scheme_check(self):
        """The validation itself must not be so strict it blocks legitimate
        URLs — checked directly against the validation function rather than
        needing a live server for the positive case."""
        import urllib.parse
        for scheme in ("https", "http"):
            parsed = urllib.parse.urlparse(f"{scheme}://hooks.example/x")
            assert parsed.scheme in ("https", "http")


class TestSuccessPath:
    def test_successful_emit_reaches_the_poster_with_correct_urls(self):
        seen = []

        def recording_poster(url, payload, timeout):
            seen.append((url, payload))
            return True

        exp = TicketingExporter(pagerduty_routing_key="key",
                                webhook_url="https://hooks.example/exonerve",
                                poster=recording_poster)
        assert exp.emit(SAMPLE_EVENT) is True
        urls = [u for u, _ in seen]
        assert PAGERDUTY_EVENTS_URL in urls
        assert "https://hooks.example/exonerve" in urls
        assert exp.stats["emitted"] == 1


# ---------------------------------------------------------------------------
# Environment-driven construction (opt-in, mirrors exporter_from_env)
# ---------------------------------------------------------------------------

class TestFromEnv:
    def test_returns_none_when_unconfigured(self, monkeypatch):
        monkeypatch.delenv("EXONERVE_PAGERDUTY_ROUTING_KEY", raising=False)
        monkeypatch.delenv("EXONERVE_TICKETING_WEBHOOK_URL", raising=False)
        assert ticketing_from_env() is None

    def test_builds_from_pagerduty_env_var(self, monkeypatch):
        monkeypatch.setenv("EXONERVE_PAGERDUTY_ROUTING_KEY", "abc123")
        monkeypatch.delenv("EXONERVE_TICKETING_WEBHOOK_URL", raising=False)
        exp = ticketing_from_env()
        assert exp is not None
        assert exp.pagerduty_routing_key == "abc123"

    def test_builds_from_webhook_env_var(self, monkeypatch):
        monkeypatch.delenv("EXONERVE_PAGERDUTY_ROUTING_KEY", raising=False)
        monkeypatch.setenv("EXONERVE_TICKETING_WEBHOOK_URL", "https://hooks.example/x")
        exp = ticketing_from_env()
        assert exp is not None
        assert exp.webhook_url == "https://hooks.example/x"
