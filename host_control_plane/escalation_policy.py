#!/usr/bin/env python3
"""
Exonerve :: Escalation Policy  (v3.11 — Incident Response, Priority 4)
=========================================================================
common/ticketing_export.py pages once, when an alert is first raised.
Nothing re-pages if that page goes unacknowledged — which is exactly the
scenario escalation exists for: the first responder is unavailable, asleep,
or the page got lost, and the incident is still sitting there untouched.

This is a small, stateless-per-call policy: on each tick, find OPEN alerts
(never acknowledged/assigned/escalated — see AlertManager.stale_open_alerts)
older than `escalate_after_s` that this policy instance hasn't already
escalated, and re-emit them to the ticketing exporter with a note marking
them as an escalation, then flip the underlying alert to ESCALATED so a
human sees that state too.

Same failure posture as everything else that touches ticketing
(common/ticketing_export.py): a broken ticketing backend, or an alert
manager call that raises, is caught and never allowed to propagate — a
misbehaving escalation check must never be able to break the control loop
that calls it periodically.
"""
from __future__ import annotations

from typing import List, Set


class EscalationPolicy:
    def __init__(self, alert_manager, ticketing_exporter,
                escalate_after_s: float = 900.0):
        self.alerts = alert_manager
        self.ticketing = ticketing_exporter
        self.escalate_after_s = escalate_after_s
        self._escalated_alert_ids: Set[str] = set()

    def check_and_escalate(self) -> List[str]:
        """Call periodically from the control loop (e.g. every heartbeat
        tick). Returns the alert_ids escalated THIS call — empty on almost
        every call, since most alerts get acknowledged well before
        `escalate_after_s`."""
        if self.ticketing is None or not self._ticketing_configured():
            return []

        try:
            stale = self.alerts.stale_open_alerts(self.escalate_after_s)
        except Exception:
            return []

        escalated: List[str] = []
        for alert in stale:
            if alert.alert_id in self._escalated_alert_ids:
                continue
            if not self._page(alert):
                continue   # ticketing failure — leave un-escalated, retry next tick
            self._escalated_alert_ids.add(alert.alert_id)
            escalated.append(alert.alert_id)
            try:
                self.alerts.escalate(alert.alert_id, by="escalation_policy")
            except Exception:
                pass   # ticketing already fired; a failed status flip isn't fatal
        return escalated

    def _ticketing_configured(self) -> bool:
        try:
            return bool(self.ticketing.configured())
        except Exception:
            return False

    def _page(self, alert) -> bool:
        try:
            return bool(self.ticketing.emit({
                "vm_id": alert.vm_id,
                "event_type": alert.event_type,
                "severity": alert.severity,
                "score": 0,
                "details": {
                    "message": (f"ESCALATION: '{alert.title}' has been open and "
                               f"unacknowledged for over {self.escalate_after_s:.0f}s"),
                    "reason": "unacknowledged_escalation",
                    "original_alert_id": alert.alert_id,
                },
                "timestamp": alert.created_at,
                "techniques": alert.techniques,
                "title": f"[ESCALATED] {alert.title}",
            }))
        except Exception:
            return False
