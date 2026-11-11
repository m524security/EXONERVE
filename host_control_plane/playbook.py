#!/usr/bin/env python3
"""
Exonerve :: Incident Response Playbook  (v3.12)
===================================================
The exact lifecycle requested: DETECT -> ISOLATE + MITIGATE -> VULN_SCAN ->
REMEDIATE -> BACKDOOR_CHECK -> RE_VALIDATE -> RECOVERY, with a SOC member
in the loop at the judgment-call stages, and "if not [recovered], always
be checking" rather than a forced close.

Design: auto-execute the FAST, REVERSIBLE stages (isolate, mitigate — these
just call whatever isolate_fn/mitigate_fn is wired in, which in the real
agent is containment.py's already-tested actions, not new logic here).
GATE the judgment-call, potentially-destructive stages (remediate, close)
behind an explicit SOC action — this module refuses to execute a
remediation or declare an incident closed on its own. Vulnerability
scanning and re-validation ("pentest again") are represented as explicit
INTEGRATION HOOKS: this module does not simulate running a real pentest —
that's an actual external tool or an actual person, and pretending
otherwise would be exactly the kind of unearned claim this project refuses
to make anywhere else. What this module does provide for real: the backdoor
check IS auto-run (BackdoorCheck is read-only and safe), but its SIGN-OFF
is still gated — findings need a human to look at them.

Layered ON TOP of IncidentManager (host_control_plane/incident_manager.py)
rather than replacing it: PlaybookStage is a finer-grained state machine
than IncidentStatus's five stages, and playbook stage transitions drive the
underlying incident's coarser status (e.g. reaching MITIGATED transitions
the incident to CONTAINED) — so the existing incident lifecycle, its
correlation logic, and its post-incident report generator all keep working
unchanged; this adds structure, it doesn't fork the data model.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Dict, List, Optional

from incident_manager import IncidentManager, IncidentStatus


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class PlaybookStage(str, Enum):
    DETECTED = "DETECTED"
    ISOLATED = "ISOLATED"                          # auto
    MITIGATED = "MITIGATED"                         # auto
    VULN_SCAN_PENDING = "VULN_SCAN_PENDING"          # awaiting SOC to trigger/record
    VULN_SCAN_COMPLETE = "VULN_SCAN_COMPLETE"
    REMEDIATION_PENDING = "REMEDIATION_PENDING"      # GATED — requires SOC approval
    REMEDIATED = "REMEDIATED"
    BACKDOOR_CHECK_PENDING = "BACKDOOR_CHECK_PENDING"    # scan auto-runs, sign-off gated
    BACKDOOR_CHECK_COMPLETE = "BACKDOOR_CHECK_COMPLETE"
    REVALIDATION_PENDING = "REVALIDATION_PENDING"     # "pentest again" — GATED
    REVALIDATED = "REVALIDATED"
    RECOVERY_CHECKING = "RECOVERY_CHECKING"           # auto, loops until healthy
    RECOVERED = "RECOVERED"
    CLOSED = "CLOSED"                                 # GATED — final SOC sign-off


# Stages a human must explicitly act on. advance_auto() is a deliberate
# no-op at every one of these — the playbook stops here and waits.
GATED_STAGES = {
    PlaybookStage.VULN_SCAN_PENDING,
    PlaybookStage.REMEDIATION_PENDING,
    PlaybookStage.BACKDOOR_CHECK_PENDING,   # scan is auto; SIGN-OFF is gated
    PlaybookStage.REVALIDATION_PENDING,
    PlaybookStage.RECOVERED,                # gates the move to CLOSED
}


class Playbook:
    def __init__(self, incident_id: str, vm_id: str,
                incident_manager: IncidentManager,
                isolate_fn: Optional[Callable[[], Dict]] = None,
                mitigate_fn: Optional[Callable[[], Dict]] = None,
                remediate_fn: Optional[Callable[[], Dict]] = None,
                health_check_fn: Optional[Callable[[], Dict]] = None,
                backdoor_check=None):
        self.incident_id = incident_id
        self.vm_id = vm_id
        self.incident_manager = incident_manager
        self.stage = PlaybookStage.DETECTED
        self._isolate_fn = isolate_fn or (lambda: {"ok": True, "message": "no-op isolate (not wired)"})
        self._mitigate_fn = mitigate_fn or (lambda: {"ok": True, "message": "no-op mitigate (not wired)"})
        self._remediate_fn = remediate_fn or (lambda: {"ok": True, "message": "no-op remediate (not wired)"})
        self._health_check_fn = health_check_fn or (lambda: {"healthy": True, "message": "no-op health check (not wired)"})
        self._backdoor_check = backdoor_check
        self._backdoor_baseline = None
        self.findings: Dict[str, List[dict]] = {
            "vuln_scan": [], "backdoor_check": [], "revalidation": [],
        }
        self.history: List[dict] = []
        self.recovery_check_count = 0

    def _log(self, event: str, by: str = "system", detail: str = "") -> None:
        self.history.append({"timestamp": _now_iso(), "event": event, "by": by, "detail": detail})
        incident = self.incident_manager.get_incident(self.incident_id)
        if incident is not None:
            incident.log(f"playbook:{event}", by, detail)

    def is_gated(self) -> bool:
        return self.stage in GATED_STAGES

    def capture_baseline(self) -> None:
        """Capture the backdoor-check baseline. Call as early as possible
        (ideally right after isolation) — a baseline captured AFTER an
        attacker has already persisted won't show their persistence as a
        change. This limitation is structural, not a bug: this module can't
        know what the host looked like before it started watching."""
        if self._backdoor_check is not None:
            self._backdoor_baseline = self._backdoor_check.snapshot()

    # -- auto-advance through the fast/reversible/health-checked stages ------

    def advance_auto(self) -> Dict:
        """Call repeatedly (e.g. every control-loop tick). A safe no-op at
        every gated stage, so it's fine to call unconditionally rather than
        needing the caller to track which stages need a manual trigger."""
        if self.stage == PlaybookStage.DETECTED:
            return self._do_isolate()
        if self.stage == PlaybookStage.ISOLATED:
            return self._do_mitigate()
        if self.stage == PlaybookStage.MITIGATED:
            return self._enter_vuln_scan_pending()
        if self.stage == PlaybookStage.VULN_SCAN_COMPLETE:
            return self._enter_remediation_pending()
        if self.stage == PlaybookStage.REMEDIATED:
            return self._run_backdoor_scan_and_wait()
        if self.stage == PlaybookStage.BACKDOOR_CHECK_COMPLETE:
            return self._enter_revalidation_pending()
        if self.stage == PlaybookStage.REVALIDATED:
            return self._enter_recovery_checking()
        if self.stage == PlaybookStage.RECOVERY_CHECKING:
            return self._do_health_check()
        return {"ok": True, "message": f"stage {self.stage.value} awaiting SOC action",
               "gated": self.is_gated()}

    def _do_isolate(self) -> Dict:
        result = self._isolate_fn() or {}
        if result.get("ok"):
            self.stage = PlaybookStage.ISOLATED
            self._log("isolated", detail=result.get("message", ""))
            self.incident_manager.transition(self.incident_id, IncidentStatus.CONTAINED,
                                            by="playbook", note="auto-isolated")
        return result

    def _do_mitigate(self) -> Dict:
        result = self._mitigate_fn() or {}
        if result.get("ok"):
            self.stage = PlaybookStage.MITIGATED
            self._log("mitigated", detail=result.get("message", ""))
        return result

    def _enter_vuln_scan_pending(self) -> Dict:
        self.stage = PlaybookStage.VULN_SCAN_PENDING
        self._log("awaiting_vuln_scan")
        return {"ok": True, "message": "awaiting SOC to trigger/record vulnerability scan"}

    def _enter_remediation_pending(self) -> Dict:
        self.stage = PlaybookStage.REMEDIATION_PENDING
        self._log("awaiting_remediation_approval")
        return {"ok": True, "message": "awaiting SOC approval before remediation executes"}

    def _run_backdoor_scan_and_wait(self) -> Dict:
        self.stage = PlaybookStage.BACKDOOR_CHECK_PENDING
        if self._backdoor_check is not None:
            current = self._backdoor_check.snapshot()
            if self._backdoor_baseline is not None:
                self.findings["backdoor_check"] = self._backdoor_check.diff(
                    self._backdoor_baseline, current)
            else:
                self.findings["backdoor_check"] = []
                self._backdoor_baseline = current
        self._log("backdoor_scan_complete_awaiting_review",
                 detail=f"{len(self.findings['backdoor_check'])} findings")
        return {"ok": True, "message": "backdoor scan complete, awaiting SOC review",
               "findings": self.findings["backdoor_check"]}

    def _enter_revalidation_pending(self) -> Dict:
        self.stage = PlaybookStage.REVALIDATION_PENDING
        self._log("awaiting_revalidation")
        return {"ok": True, "message": "awaiting SOC re-validation (pentest again)"}

    def _enter_recovery_checking(self) -> Dict:
        self.stage = PlaybookStage.RECOVERY_CHECKING
        self._log("recovery_checking_started")
        return self._do_health_check()

    def _do_health_check(self) -> Dict:
        self.recovery_check_count += 1
        result = self._health_check_fn() or {}
        if result.get("healthy"):
            self.stage = PlaybookStage.RECOVERED
            self._log("recovered", detail=result.get("message", ""))
            self.incident_manager.transition(self.incident_id, IncidentStatus.RECOVERED,
                                            by="playbook", note="health check passed")
        else:
            # STAYS in RECOVERY_CHECKING — "if not [recovered], always be
            # checking" rather than declaring recovery on a schedule.
            self._log("recovery_check_failed_will_retry", detail=result.get("message", ""))
        return result

    # -- gated SOC actions ----------------------------------------------------

    def trigger_vuln_scan(self, findings: List[dict], by: str = "analyst") -> Dict:
        """Record vulnerability-scan findings. This does NOT run a scan —
        that's an actual scanner (Nessus/OpenVAS/nmap/whatever the org
        already uses) or a human pentester; this records the OUTPUT."""
        if self.stage != PlaybookStage.VULN_SCAN_PENDING:
            return self._wrong_stage_error(PlaybookStage.VULN_SCAN_PENDING)
        self.findings["vuln_scan"] = findings
        self.stage = PlaybookStage.VULN_SCAN_COMPLETE
        self._log("vuln_scan_recorded", by, f"{len(findings)} findings")
        return {"ok": True, "message": f"{len(findings)} vulnerability finding(s) recorded"}

    def approve_remediation(self, by: str = "analyst", note: str = "") -> Dict:
        """The one gate that matters most: nothing patches, reconfigures,
        or changes anything until a human explicitly approves it here."""
        if self.stage != PlaybookStage.REMEDIATION_PENDING:
            return self._wrong_stage_error(PlaybookStage.REMEDIATION_PENDING)
        result = self._remediate_fn() or {}
        self.stage = PlaybookStage.REMEDIATED
        self._log("remediation_approved_and_executed", by, note)
        return result

    def approve_backdoor_check(self, by: str = "analyst", note: str = "") -> Dict:
        if self.stage != PlaybookStage.BACKDOOR_CHECK_PENDING:
            return self._wrong_stage_error(PlaybookStage.BACKDOOR_CHECK_PENDING)
        self.stage = PlaybookStage.BACKDOOR_CHECK_COMPLETE
        self._log("backdoor_check_signed_off", by, note)
        return {"ok": True, "message": "backdoor check signed off"}

    def complete_revalidation(self, findings: List[dict], by: str = "analyst") -> Dict:
        """Records re-validation ('pentest again') findings — same posture
        as trigger_vuln_scan: this records a real test's output, it doesn't
        run one."""
        if self.stage != PlaybookStage.REVALIDATION_PENDING:
            return self._wrong_stage_error(PlaybookStage.REVALIDATION_PENDING)
        self.findings["revalidation"] = findings
        self.stage = PlaybookStage.REVALIDATED
        self._log("revalidation_recorded", by, f"{len(findings)} findings")
        return {"ok": True, "message": f"{len(findings)} re-validation finding(s) recorded"}

    def close(self, by: str = "analyst", note: str = "") -> Dict:
        if self.stage != PlaybookStage.RECOVERED:
            return self._wrong_stage_error(PlaybookStage.RECOVERED)
        self.stage = PlaybookStage.CLOSED
        self._log("closed", by, note)
        self.incident_manager.transition(self.incident_id, IncidentStatus.CLOSED, by=by, note=note)
        return {"ok": True, "message": "playbook closed"}

    def reopen_to(self, stage: PlaybookStage, by: str = "analyst", reason: str = "") -> Dict:
        """Escape hatch: if backdoor-check or re-validation turns up
        something wrong, a SOC member sends the case back to an earlier
        stage rather than the playbook forcing a strictly linear path.
        Real incident response loops; this lets it."""
        old = self.stage
        self.stage = stage
        self._log(f"reopened_from_{old.value.lower()}_to_{stage.value.lower()}", by, reason)
        return {"ok": True, "message": f"reopened: {old.value} -> {stage.value}"}

    def _wrong_stage_error(self, expected: PlaybookStage) -> Dict:
        return {"ok": False, "message": (
            f"expected stage {expected.value}, currently at {self.stage.value}")}

    def to_dict(self) -> Dict:
        return {
            "incident_id": self.incident_id, "vm_id": self.vm_id,
            "stage": self.stage.value, "is_gated": self.is_gated(),
            "recovery_check_count": self.recovery_check_count,
            "findings": self.findings,
            "history": self.history[-30:],
        }


def make_default_playbook(incident_id: str, vm_id: str,
                          incident_manager: IncidentManager,
                          hypervisor, backdoor_check=None,
                          quiet_period_s: float = 300.0) -> Playbook:
    """Wires isolate/mitigate to the SAME hypervisor calls control_center.py's
    own decision-handling already uses (`hypervisor.block_network`) — this is
    orchestration on top of existing, already-tested actions, not a new
    implementation of them.

    HONEST LIMITATION on health_check_fn, found while wiring this up: there
    is no read-only "are this VM's services actually healthy" query on the
    hypervisor interface — only action-triggering calls like
    restore_snapshot(). Using an action call inside something a loop polls
    repeatedly would re-trigger that action on every tick, which is a real
    bug, not a design choice — caught here before it shipped. What this
    checks instead, honestly: whether the incident has generated any NEW
    detection activity in the last `quiet_period_s` (default 5 min), using
    IncidentManager's own last_activity_ts. That is a genuine, non-
    destructive signal ("nothing new is happening"), but it is NOT the same
    claim as "the VM's actual services are confirmed running" — this agent
    has no RPC for that today. Named as a real gap, not silently assumed
    away: see DEFENSE_GUIDE.md / CHANGELOG.md for the open item.

    `remediate_fn` is deliberately left as the safe no-op default even here:
    "remove the vulnerability" is an org-specific action (patch, config
    change, package update) this module has no way to perform generically
    and should not guess at. Wire a real one in when integrating with an
    actual patch/config-management system.
    """
    def isolate_fn() -> Dict:
        result = hypervisor.block_network(vm_id)
        return {"ok": result.success, "message": result.message}

    def mitigate_fn() -> Dict:
        # "Mitigate" here means re-confirming the reversible containment
        # step already available on the hypervisor interface — NOT
        # remediation, and NOT a destructive recovery action.
        result = hypervisor.block_network(vm_id)
        return {"ok": result.success, "message": f"mitigation re-confirmed: {result.message}"}

    def health_check_fn() -> Dict:
        incident = incident_manager.get_incident(incident_id)
        if incident is None:
            return {"healthy": False, "message": "incident record missing"}
        quiet_for = time.time() - incident.last_activity_ts
        healthy = quiet_for >= quiet_period_s
        return {"healthy": healthy,
               "message": (f"no new detection activity for {quiet_for:.0f}s "
                          f"(need {quiet_period_s:.0f}s) — NOTE: this checks "
                          f"absence of new alerts, not confirmed service "
                          f"health; see make_default_playbook's docstring")}

    return Playbook(incident_id, vm_id, incident_manager,
                    isolate_fn=isolate_fn, mitigate_fn=mitigate_fn,
                    health_check_fn=health_check_fn,
                    backdoor_check=backdoor_check)
