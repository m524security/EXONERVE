#!/usr/bin/env python3
"""
Exonerve :: Ticketing / On-Call Export  (v3.10, Priority 1.2)
==================================================================
SIEM export (common/siem_export.py) gets detections into a log pipeline.
Nothing in that path pages a human — an analyst only finds out if they
happen to be looking at the dashboard or the SIEM at the right moment. This
module closes that specific gap: when AlertManager raises an actual triage
alert (already deduped, already above ALERT_MIN_DELTA — see
host_control_plane/alert_manager.py), forward it to a real on-call system.

Two backends, either or both may be configured at once:

  * PagerDuty Events API v2   -- EXONERVE_PAGERDUTY_ROUTING_KEY
  * Generic webhook           -- EXONERVE_TICKETING_WEBHOOK_URL
    Covers Opsgenie / ServiceNow / Jira / Slack-via-workflow -- all of them
    accept an arbitrary inbound HTTPS POST through their own "generic
    webhook" / "inbound integration" feature. This module does not attempt
    to guess three different vendor request schemas; it sends one clean,
    stable JSON body and lets the receiving automation do its own field
    mapping, which is what that feature is for.

Same failure posture as siem_export.py, restated because it's the whole
point of this module existing: a dead or slow ticketing endpoint must NEVER
be able to break detection, scoring, or containment. Every network call is
wrapped; every failure is caught, counted, and logged — never raised into
the caller.

Stdlib only (urllib). No SDK, no vendor lock-in, no network dependency at
import time.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone
from typing import Callable, Dict, Optional

PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

# PagerDuty's Events API v2 constrains payload.severity to exactly these four
# values (https://developer.pagerduty.com/docs/db0fa8c8984fc-send-an-event).
# Exonerve's four-level severity is mapped onto that set, not passed through
# raw — an unmapped/misspelled severity would be silently rejected by PD.
_PD_SEVERITY = {"low": "info", "medium": "warning", "high": "error", "critical": "critical"}

_VALID_ACTIONS = ("trigger", "acknowledge", "resolve")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def to_pagerduty_event(event: Dict, routing_key: str, *,
                        client: str = "Exonerve",
                        client_url: Optional[str] = None,
                        event_action: str = "trigger") -> Dict:
    """Build a PagerDuty Events API v2 payload.

    Schema: https://developer.pagerduty.com/docs/db0fa8c8984fc-send-an-event
    """
    if event_action not in _VALID_ACTIONS:
        raise ValueError(f"event_action must be one of {_VALID_ACTIONS}, got {event_action!r}")
    if not routing_key:
        raise ValueError("routing_key is required")

    details = event.get("details") or {}
    vm_id = event.get("vm_id", "unknown")
    etype = event.get("event_type", "unknown")
    sev = _PD_SEVERITY.get(str(event.get("severity", "medium")).lower(), "warning")
    summary = details.get("message") or event.get("title") or etype

    # A stable dedup_key means repeated pages for the SAME ongoing issue on
    # the SAME VM correlate into one PagerDuty incident instead of paging
    # on-call again for every individual event of that type.
    dedup_key = f"exonerve:{vm_id}:{etype}"

    payload: Dict = {
        "routing_key": routing_key,
        "event_action": event_action,
        "dedup_key": dedup_key,
        "payload": {
            # PagerDuty caps summary at 1024 characters.
            "summary": f"[Exonerve] {summary}"[:1024],
            "source": f"exonerve:{vm_id}",
            "severity": sev,
            "timestamp": event.get("timestamp") or _now_iso(),
            "component": etype,
            "group": vm_id,
            "class": event.get("verdict", etype),
            "custom_details": {
                "score": event.get("score", 0),
                "techniques": event.get("techniques", []),
                "details": details,
            },
        },
        "client": client,
    }
    if client_url:
        payload["client_url"] = client_url
    return payload


def to_generic_webhook_payload(event: Dict) -> Dict:
    """Plain structured JSON for the generic-webhook backend.

    Deliberately NOT vendor-shaped. Opsgenie / ServiceNow / Jira are reached
    through THEIR generic inbound-webhook or automation-rule feature, which
    accepts arbitrary JSON and does its own field mapping on the receiving
    end — guessing three vendor schemas here would be more likely to
    silently break than to help.
    """
    details = event.get("details") or {}
    return {
        "source": "exonerve",
        "vm_id": event.get("vm_id", "unknown"),
        "event_type": event.get("event_type", "unknown"),
        "severity": event.get("severity", "medium"),
        "score": event.get("score", 0),
        "title": details.get("message") or event.get("title") or event.get("event_type"),
        "techniques": event.get("techniques", []),
        "details": details,
        "timestamp": event.get("timestamp") or _now_iso(),
    }


def _default_poster(url: str, payload: Dict, timeout: float) -> bool:
    """Real network transport. Swapped out in tests via the `poster=` param
    so failure handling can be proven without touching the network.

    v3.13 security fix (bandit B310): urllib.request.urlopen() will happily
    open file:// and other unexpected schemes if given one — normally not
    reachable here since PAGERDUTY_EVENTS_URL is a hardcoded constant and
    webhook_url is operator-configured, not attacker-controlled at request
    time, but a misconfigured or copy-pasted webhook_url is a realistic
    operator mistake worth guarding against explicitly rather than trusting
    the input implicitly.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https", "http"):
        raise ValueError(f"refusing to POST to non-HTTP(S) scheme: {parsed.scheme!r} "
                         f"(url={url!r}) — check EXONERVE_TICKETING_WEBHOOK_URL / "
                         f"the configured webhook URL for a typo")
    data = json.dumps(payload, default=str).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", "User-Agent": "Exonerve"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310 - scheme validated above
        status = getattr(resp, "status", None) or getattr(resp, "code", 200)
        return 200 <= status < 300


class TicketingExporter:
    """Thread-safe. Never raises into the caller.

    `poster` is injectable (real network transport by default) specifically
    so tests can simulate a failed HTTP call without a live endpoint —
    matching how WebServiceC2Detector injects its DNS resolver elsewhere in
    this codebase, for the same reason.
    """

    def __init__(self,
                 pagerduty_routing_key: Optional[str] = None,
                 webhook_url: Optional[str] = None,
                 client_name: str = "Exonerve",
                 client_url: Optional[str] = None,
                 timeout: float = 5.0,
                 enabled: bool = True,
                 poster: Optional[Callable[[str, Dict, float], bool]] = None):
        self.pagerduty_routing_key = pagerduty_routing_key
        self.webhook_url = webhook_url
        self.client_name = client_name
        self.client_url = client_url
        self.timeout = timeout
        self.enabled = enabled
        self._poster = poster or _default_poster
        self._lock = threading.Lock()
        self.stats = {"emitted": 0, "pagerduty_errors": 0, "webhook_errors": 0, "dropped": 0}

    def configured(self) -> bool:
        return bool(self.pagerduty_routing_key or self.webhook_url)

    def emit(self, event: Dict) -> bool:
        """Page/ticket one alert. Returns True if it landed anywhere.

        Never raises — a broken ticketing integration is an operational
        problem to notice in `self.stats`, not a reason detection or
        containment should fail.
        """
        if not self.enabled or not self.configured():
            return False

        landed = False
        if self.pagerduty_routing_key:
            landed |= self._send_pagerduty(event)
        if self.webhook_url:
            landed |= self._send_webhook(event)

        with self._lock:
            if landed:
                self.stats["emitted"] += 1
            else:
                self.stats["dropped"] += 1
        return landed

    def _send_pagerduty(self, event: Dict) -> bool:
        try:
            payload = to_pagerduty_event(event, self.pagerduty_routing_key,
                                          client=self.client_name,
                                          client_url=self.client_url)
        except Exception:
            with self._lock:
                self.stats["dropped"] += 1
            return False
        return self._post(PAGERDUTY_EVENTS_URL, payload, "pagerduty_errors")

    def _send_webhook(self, event: Dict) -> bool:
        try:
            payload = to_generic_webhook_payload(event)
        except Exception:
            with self._lock:
                self.stats["dropped"] += 1
            return False
        return self._post(self.webhook_url, payload, "webhook_errors")

    def _post(self, url: str, payload: Dict, error_stat: str) -> bool:
        try:
            return bool(self._poster(url, payload, self.timeout))
        except Exception:
            with self._lock:
                self.stats[error_stat] += 1
            return False


def ticketing_from_env() -> Optional[TicketingExporter]:
    """Build an exporter from environment, or None if ticketing export is off.

    EXONERVE_PAGERDUTY_ROUTING_KEY   PagerDuty Events API v2 integration key
    EXONERVE_TICKETING_WEBHOOK_URL   generic inbound webhook URL
    EXONERVE_TICKETING_CLIENT_URL    optional deep link back to the dashboard,
                                      sent to PagerDuty as `client_url`
    """
    pd_key = os.environ.get("EXONERVE_PAGERDUTY_ROUTING_KEY")
    webhook = os.environ.get("EXONERVE_TICKETING_WEBHOOK_URL")
    client_url = os.environ.get("EXONERVE_TICKETING_CLIENT_URL")
    if not pd_key and not webhook:
        return None
    try:
        return TicketingExporter(pagerduty_routing_key=pd_key, webhook_url=webhook,
                                  client_url=client_url)
    except Exception:
        return None
