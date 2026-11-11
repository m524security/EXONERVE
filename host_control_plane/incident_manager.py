#!/usr/bin/env python3
"""
Exonerve :: Incident Case Management  (v3.11 — Incident Response, Priority 1 & 3)
====================================================================================
Alerts (alert_manager.py) are point-in-time triage items — one row in a queue.
Nothing before this grouped a burst of related alerts on one VM into a single
INCIDENT with a lifecycle a responder actually works through:

    DETECTED -> TRIAGED -> CONTAINED -> RECOVERED -> CLOSED

This module is deliberately a thin correlation + lifecycle layer over
primitives that already exist and are already tested elsewhere in this repo —
it does not duplicate detection, scoring, or containment logic:

  - Alerts come from AlertManager (already deduped, already scored, already
    has its own dedupe window — this is a WIDER correlation on top of that,
    not a replacement for it).
  - Containment/failover actions come from CorrelationEngine's VMState.ir_log,
    which is already populated as actions happen. This module reads that
    list when building a report; it does not keep a second copy of it.
  - The kill-chain narrative comes from KillChainReconstructor
    (blue_team/killchain_reconstructor/).
  - The ATT&CK Navigator layer comes from common/attack_navigator.py.
  - The STIX bundle comes from common/stix_export.py.

Reusing those four instead of re-deriving kill-chain ordering or STIX object
shapes a second time is the same design discipline the wiper detector used in
v3.9 (reusing the file-monitor's deletion stream instead of standing up a
parallel one) — correct engineering, not duplicated effort.

Thread-safe. No external dependencies.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Set


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class IncidentStatus(str, Enum):
    DETECTED = "DETECTED"
    TRIAGED = "TRIAGED"
    CONTAINED = "CONTAINED"
    RECOVERED = "RECOVERED"
    CLOSED = "CLOSED"


_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _max_severity(a: str, b: str) -> str:
    return a if _SEVERITY_RANK.get(a, 0) >= _SEVERITY_RANK.get(b, 0) else b


# Which transitions are allowed from each status. CLOSED is terminal by
# design: a new alert on the same VM after closure opens a NEW incident
# (linked to the closed one for context) rather than silently reopening a
# case that was already signed off — mirrors how a real SOC treats it.
_ALLOWED_TRANSITIONS: Dict[IncidentStatus, Set[IncidentStatus]] = {
    IncidentStatus.DETECTED:  {IncidentStatus.TRIAGED, IncidentStatus.CONTAINED, IncidentStatus.CLOSED},
    IncidentStatus.TRIAGED:   {IncidentStatus.CONTAINED, IncidentStatus.CLOSED},
    IncidentStatus.CONTAINED: {IncidentStatus.TRIAGED, IncidentStatus.RECOVERED, IncidentStatus.CLOSED},
    IncidentStatus.RECOVERED: {IncidentStatus.CONTAINED, IncidentStatus.CLOSED},
    IncidentStatus.CLOSED:    set(),
}


@dataclass
class Incident:
    incident_id: str
    vm_id: str
    status: IncidentStatus
    opened_at: str
    opened_ts: float
    last_activity_ts: float
    closed_at: Optional[str] = None
    alert_ids: List[str] = field(default_factory=list)
    technique_counts: Dict[str, int] = field(default_factory=dict)
    severity_peak: str = "low"
    linked_incident_ids: List[str] = field(default_factory=list)
    history: List[dict] = field(default_factory=list)

    def log(self, action: str, by: str = "system", extra: str = "") -> None:
        self.history.append({"timestamp": _now_iso(), "action": action,
                             "by": by, "extra": extra})

    def to_dict(self) -> dict:
        end_ts = self.last_activity_ts if self.status == IncidentStatus.CLOSED else time.time()
        return {
            "incident_id": self.incident_id,
            "vm_id": self.vm_id,
            "status": self.status.value,
            "opened_at": self.opened_at,
            "closed_at": self.closed_at,
            "alert_count": len(self.alert_ids),
            "alert_ids": list(self.alert_ids),
            "technique_ids": sorted(self.technique_counts.keys()),
            "technique_counts": dict(self.technique_counts),
            "severity_peak": self.severity_peak,
            "linked_incident_ids": list(self.linked_incident_ids),
            "history": list(self.history[-20:]),
            "duration_seconds": round(max(0.0, end_ts - self.opened_ts), 1),
        }


class IncidentManager:
    """Correlates alerts from the same VM into a case, tracks its lifecycle,
    and can produce a post-incident report from tools that already exist
    elsewhere in this repo."""

    CORRELATION_WINDOW_S = 1800.0   # alerts on the same VM join the currently
                                     # open case if the gap since that case's
                                     # last activity is under 30 min; a bigger
                                     # gap opens a new incident instead

    def __init__(self, correlation_window_s: float = CORRELATION_WINDOW_S):
        self._lock = threading.RLock()
        self._incidents: Dict[str, Incident] = {}
        self._open_by_vm: Dict[str, str] = {}   # vm_id -> incident_id, only while open
        self._seq = 0
        self.correlation_window_s = correlation_window_s

    # -- ingestion ------------------------------------------------------------

    def ingest_alert(self, alert) -> Incident:
        """`alert` is an alert_manager.Alert (duck-typed on .alert_id,
        .vm_id, .severity, .techniques — so tests can pass a lightweight
        stand-in without constructing a full AlertManager). Attaches it to
        an open, recently-active incident for this VM, or opens a new one."""
        with self._lock:
            incident = self._find_open_incident(alert.vm_id)
            if incident is None:
                incident = self._open_incident(alert.vm_id)

            incident.alert_ids.append(alert.alert_id)
            incident.last_activity_ts = time.time()
            incident.severity_peak = _max_severity(incident.severity_peak, alert.severity)
            for t in (alert.techniques or []):
                tid = t.get("id") if isinstance(t, dict) else None
                if tid:
                    incident.technique_counts[tid] = incident.technique_counts.get(tid, 0) + 1
            incident.log("alert_attached", extra=alert.alert_id)
            return incident

    def _find_open_incident(self, vm_id: str) -> Optional[Incident]:
        iid = self._open_by_vm.get(vm_id)
        if not iid:
            return None
        incident = self._incidents.get(iid)
        if incident is None or incident.status == IncidentStatus.CLOSED:
            return None
        if (time.time() - incident.last_activity_ts) > self.correlation_window_s:
            return None
        return incident

    def _open_incident(self, vm_id: str) -> Incident:
        self._seq += 1
        iid = f"INC-{self._seq:05d}"
        now = time.time()
        incident = Incident(
            incident_id=iid, vm_id=vm_id, status=IncidentStatus.DETECTED,
            opened_at=_now_iso(), opened_ts=now, last_activity_ts=now,
        )
        prior = self._most_recent_closed(vm_id)
        if prior:
            incident.linked_incident_ids.append(prior.incident_id)
        incident.log("opened")
        self._incidents[iid] = incident
        self._open_by_vm[vm_id] = iid
        return incident

    def _most_recent_closed(self, vm_id: str) -> Optional[Incident]:
        closed = [i for i in self._incidents.values()
                 if i.vm_id == vm_id and i.status == IncidentStatus.CLOSED]
        return max(closed, key=lambda i: i.opened_ts) if closed else None

    # -- lifecycle --------------------------------------------------------------

    def transition(self, incident_id: str, new_status: IncidentStatus,
                   by: str = "analyst", note: str = "") -> dict:
        with self._lock:
            incident = self._incidents.get(incident_id)
            if incident is None:
                return {"ok": False, "message": "incident not found"}
            allowed = _ALLOWED_TRANSITIONS.get(incident.status, set())
            if new_status not in allowed:
                return {"ok": False, "message": (
                    f"cannot move {incident_id} from {incident.status.value} to "
                    f"{new_status.value}; allowed: {sorted(s.value for s in allowed)}")}
            incident.status = new_status
            incident.log(f"transitioned_to_{new_status.value.lower()}", by, note)
            if new_status == IncidentStatus.CLOSED:
                incident.closed_at = _now_iso()
                incident.last_activity_ts = time.time()
                if self._open_by_vm.get(incident.vm_id) == incident_id:
                    del self._open_by_vm[incident.vm_id]
            return {"ok": True, "message": f"{incident_id} -> {new_status.value}"}

    # -- queries ------------------------------------------------------------------

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        return self._incidents.get(incident_id)

    def list_incidents(self, status: Optional[IncidentStatus] = None,
                       vm_id: Optional[str] = None) -> List[dict]:
        with self._lock:
            items = list(self._incidents.values())
            if status is not None:
                items = [i for i in items if i.status == status]
            if vm_id is not None:
                items = [i for i in items if i.vm_id == vm_id]
            items.sort(key=lambda i: i.opened_ts, reverse=True)
            return [i.to_dict() for i in items]

    # -- post-incident report (Priority 3) -----------------------------------------

    def generate_report(self, incident_id: str, out_dir: str,
                        ir_log: Optional[List[dict]] = None) -> dict:
        """Stitches together tools that already exist elsewhere in this repo
        into one report directory. Does not reimplement any of their logic.

        `ir_log` is the VM's containment/failover action log — pass in
        `VMState.ir_log` from CorrelationEngine. Taking it as a parameter rather
        than importing control_center.py keeps this module usable (and
        testable) with zero dependency on the control plane's HTTP server,
        hypervisor backends, or failover orchestrator.
        """
        incident = self.get_incident(incident_id)
        if incident is None:
            raise ValueError(f"unknown incident: {incident_id}")

        # Imported here rather than at module load: a caller that only wants
        # lifecycle tracking (most of this module's tests) never needs to
        # import the ATT&CK/STIX/kill-chain machinery to do that.
        _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if _repo_root not in sys.path:
            sys.path.insert(0, _repo_root)
        from blue_team.killchain_reconstructor.killchain_reconstructor import (
            KillChainReconstructor,
        )
        from common.attack_navigator import live_layer, write_layer
        from common.stix_export import build_bundle, write_bundle

        os.makedirs(out_dir, exist_ok=True)
        technique_ids = sorted(incident.technique_counts.keys())

        kill_chain = KillChainReconstructor().reconstruct(technique_ids)

        layer = live_layer(incident.technique_counts)
        layer_path = write_layer(
            layer, os.path.join(out_dir, f"{incident_id}_navigator_layer.json"))

        bundle = build_bundle(technique_ids=technique_ids or None)
        bundle_path = write_bundle(
            bundle, os.path.join(out_dir, f"{incident_id}_stix_bundle.json"))

        md = self._render_markdown(incident, kill_chain, ir_log or [])
        md_path = os.path.join(out_dir, f"{incident_id}_report.md")
        with open(md_path, "w", encoding="utf-8") as f:
            f.write(md)

        return {
            "incident_id": incident_id,
            "markdown_path": md_path,
            "navigator_layer_path": layer_path,
            "stix_bundle_path": bundle_path,
            "kill_chain": kill_chain.to_dict(),
        }

    @staticmethod
    def _render_markdown(incident: Incident, kill_chain, ir_log: List[dict]) -> str:
        d = incident.to_dict()
        lines = [
            f"# Post-Incident Report — {d['incident_id']}",
            "",
            f"**VM:** `{d['vm_id']}`  ",
            f"**Status:** {d['status']}  ",
            f"**Opened:** {d['opened_at']}  ",
            f"**Closed:** {d['closed_at'] or '(still open)'}  ",
            f"**Duration:** {d['duration_seconds']:.0f}s  ",
            f"**Peak severity:** {d['severity_peak']}  ",
            f"**Alerts in this case:** {d['alert_count']} "
            f"({', '.join(d['alert_ids']) or 'none'})  ",
        ]
        if d["linked_incident_ids"]:
            lines.append(f"**Linked prior incident(s):** "
                         f"{', '.join(d['linked_incident_ids'])}  ")
        lines += ["", "## Kill-chain reconstruction", "", kill_chain.narrative(), ""]
        lines += ["## ATT&CK techniques observed", ""]
        if d["technique_ids"]:
            for tid in d["technique_ids"]:
                lines.append(f"- `{tid}` — seen {d['technique_counts'][tid]}x")
        else:
            lines.append("_None mapped._")
        lines += ["", "## Response actions taken", ""]
        if ir_log:
            for entry in ir_log:
                status = "DONE" if entry.get("success") else "FAILED"
                lines.append(f"- [{status}] `{entry.get('timestamp', '')}` "
                             f"**{entry.get('operation', '?')}** — "
                             f"{entry.get('message', '')}")
        else:
            lines.append("_No containment/failover actions recorded for this VM._")
        lines += ["", "## Case timeline", ""]
        for h in d["history"]:
            lines.append(f"- `{h['timestamp']}` **{h['action']}** "
                         f"({h['by']}) {h.get('extra', '')}")
        lines += [
            "", "---",
            "_Generated by `host_control_plane/incident_manager.py`. This report "
            "reflects only what this agent directly observed and acted on; it is "
            "a starting point for a responder's writeup, not a replacement for "
            "one. Chain-of-custody for any collected forensic artifacts is NOT "
            "covered here — see DEFENSE_GUIDE.md's Open Items for that gap._",
        ]
        return "\n".join(lines)
