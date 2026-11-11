#!/usr/bin/env python3
"""
Exonerve :: Control Center  (v2)
======================================
Host Control Plane (VLAN 20). Always-active, aggressive auto-response.

Threads:
  T1  Telemetry server   — receives AUTHENTICATED agent frames (SecureReceiver),
                            rejects replays / spoofed identities, feeds the engine.
  T2  Flask SOC Dashboard — real-time command view + control API (port 5000).
  T3  Watchdog           — "always active aggression": flags agents that go
                            silent (malware's first move is to kill the agent)
                            and escalates score for unexplained silence.
  Main IR worker         — drains the isolation queue and runs the response
                            sequence ASYNCHRONOUSLY so the engine never blocks.

Response on threat (auto or manual):
  1. BLOCK   instant NIC kill-switch (stops C2/exfil in ms)
  2. ISOLATE move to quarantine VLAN
  3. DUMP    capture RAM for forensics
  4. FAILOVER promote a warm standby so the WORKLOAD KEEPS RUNNING
  5. RESTORE rollback the infected VM to a clean golden snapshot
  6. REJOIN  cured VM comes back as the new standby (self-healing)

Key fixes vs v1:
  - Authenticated transport (no more forgeable XOR / vm_id spoofing).
  - Correct scoring: crypto_spike=50, velocity=20 (was silently 40), shell vs
    process split honoured; agent score_delta is NEVER trusted as a fallback.
  - IR runs in a worker thread, so the dashboard shows IR-log progress live
    instead of freezing for ~9s.
  - Per-VM lock discipline avoids holding the global lock during slow hypervisor
    calls.
"""

import argparse
import hmac
import logging
import os
import re
import secrets
import socketserver
import struct
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from flask import Flask, jsonify, Response

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from hypervisor_api import HypervisorAPI, load_default_config  # noqa: E402
from failover_orchestrator import FailoverOrchestrator, SimulatedBackend  # noqa: E402
from common.secure_channel import SecureReceiver, AuthError, load_master_secret  # noqa: E402
from common.mitre_attack import map_event_to_techniques, matrix_state  # noqa: E402
from decision_engine import DecisionEngine, Fact  # noqa: E402  (deterministic, non-AI)
from alert_manager import AlertManager  # noqa: E402
from common.siem_export import exporter_from_env  # noqa: E402
from common.ticketing_export import ticketing_from_env  # noqa: E402
from incident_manager import IncidentManager, IncidentStatus  # noqa: E402
from playbook import Playbook, make_default_playbook, PlaybookStage  # noqa: E402
from escalation_policy import EscalationPolicy  # noqa: E402
from geo_intel import enrich_ip  # noqa: E402

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("exonerve.control")

# ---------------------------------------------------------------------------
# Scoring — single source of truth (agent-supplied deltas are NEVER trusted)
# ---------------------------------------------------------------------------
ESCALATE_AFTER_S = 900.0   # re-page an OPEN, unacknowledged alert after 15 min

SCORE_WEIGHTS = {
    "crypto_spike": 50,   # ransomware mass-encryption signature (highest signal)
    "entropy":      40,   # single high-entropy file write
    "shadow":       40,   # backup / shadow-copy destruction
    "process":      40,   # execution from suspicious path
    "shell":        30,   # web server spawning a shell (RCE / webshell)
    "agent_silence": 25,  # agent went dark — possible defense evasion (T1562.001)
    "velocity":     20,   # file-modification velocity spike
    "network":      15,   # unexpected outbound connection (C2 / beacon)
    "heartbeat":     0,
    # --- current-threat event types ---
    "cred_dump":    50,   # LSASS credential dumping (T1003.001) — pre-ransomware staple
    "driver_load":  45,   # BYOVD: vulnerable signed driver loaded (T1068)
    "cloud_exfil":  45,   # bulk exfil to cloud storage (T1567.002)
    "ext_rename":   50,   # mass extension rename to .locked/.wncry (T1486)
    "slow_encrypt": 45,   # throttled encryption below burst threshold (T1486)
    # --- modern threat event types (v3.9) ---
    "reverse_shell":    50,  # shell stdio bound to a socket (T1059.004)
    "container_escape": 50,  # runtime socket / hostPath reach-through (T1611)
    "browser_cred_theft": 50,# infostealer on browser cred+cookie store (T1555.003)
    "data_destruction": 50,  # mass deletion / wiper (T1485)
    "imds_access":      45,  # cloud metadata credential theft (T1552.005)
    "cred_file_access": 45,  # cloud/CI credential file read (T1552.001)
    "k8s_token_access": 45,  # service-account token theft (T1552.007) — nosec B105: bandit's heuristic matches "token" in the KEY against this integer SCORE WEIGHT, not a credential
    "supply_chain":     45,  # package manager spawned a payload (T1195.002)
    "ssh_persistence":  45,  # authorized_keys backdoor (T1098.004)
    "cryptominer":      40,  # resource hijacking (T1496)
    "log_tamper":       40,  # log/history destruction (T1070.002/.003)
    "web_service_c2":   35,  # C2 over legitimate SaaS (T1102.002)
    "tunnel":           30,  # reverse tunnel exposure (T1572)
    "ransomware_esxi": 50, # hypervisor/ESXi datastore encryption (T1486)
    # --- v3.10 event types ---
    "ext_rate_spike":   45,  # novel-extension-rate spike; catches per-file
                             # randomised ransomware extensions (T1486)
    "beacon":           35,  # regular-interval low-volume C2 beaconing,
                             # independent of egress volume (T1071)
    # --- v3.12 event types ---
    "exfil_graph":      40,  # sensitive-file-access-then-new-egress (T1020)
    "honeytoken_accessed": 55,  # near-zero-FP by design: nothing legitimate
                                 # has a reason to touch a planted decoy file
    "kerberoast":   35,   # SPN ticket harvesting (T1558.003)
    "rmm_tool":     30,   # unsanctioned remote-access tool (T1219)
    "powershell":   30,   # encoded/obfuscated PowerShell (T1059.001 / T1027)
    "lolbin":       30,   # signed-binary proxy execution (T1218)
    "staging":      25,   # data archived for exfil (T1560)
    "persistence":  25,   # scheduled task / WMI / new account (T1053/T1546.003/T1136)
    "mfa_fatigue":  25,   # MFA push-bombing (T1621)
    "cloud_auth":   20,   # anomalous cloud logon / impossible travel (T1078.004)
}
ISOLATION_THRESHOLD = 100
# Unambiguous, high-confidence signals that justify an immediate NIC hard-block
# before the full score even accrues (cut C2/exfil in milliseconds).
INSTANT_BLOCK_TYPES = {"crypto_spike", "cred_dump", "ransomware_esxi",
                       "reverse_shell", "container_escape", "data_destruction"}
# NOTE (v3.8): ext_rename and slow_encrypt are deliberately NOT in the instant
# -block set. Both are high-confidence, but an instant NIC kill on a production
# host is expensive and both have plausible benign analogues (a build tool
# emitting an unusual artifact extension; an admin bulk-encrypting a share with
# gpg). They score 50/45, so one corroborating signal crosses the isolation
# threshold. Operators who prefer speed over caution can add them here.
ROLLING_WINDOW_SECS = 60
MAX_EVENTS_PER_VM = 500
# Watchdog: an agent that misses this many expected heartbeats is "silent".
SILENCE_GRACE_MULTIPLIER = 3.0   # missed beats = (now - last_seen) / interval


def _resolve_delta(event_type: str, details: dict) -> int:
    """Authoritative score for an event. Ignores any agent-claimed delta."""
    if event_type == "process":
        if details.get("reason") == "web_server_spawned_shell":
            return SCORE_WEIGHTS["shell"]
        return SCORE_WEIGHTS["process"]
    # Credential-access events share one event_type; reason tunes the weight.
    if event_type == "cred_dump" and details.get("reason") == "kerberoast":
        return SCORE_WEIGHTS["kerberoast"]
    return SCORE_WEIGHTS.get(event_type, 0)


# ---------------------------------------------------------------------------
# Per-VM state
# ---------------------------------------------------------------------------

@dataclass
class ScoredEvent:
    timestamp:   float
    event_type:  str
    severity:    str
    score_delta: int
    details:     dict
    raw_event:   dict


@dataclass
class VMState:
    vm_id:           str
    threat_score:    int = 0
    status:          str = "SECURE"          # SECURE|WARNING|CRITICAL|ISOLATED|QUARANTINE_UNENFORCED
    isolated:        bool = False            # the system DECIDED to isolate (logical intent)
    isolation_enforced: bool = False         # a real containment action actually succeeded
    isolation_detail: str = ""               # human-readable truth about what was/wasn't enforced
    silent:          bool = False            # watchdog: agent went quiet
    last_seen:       float = 0.0
    last_hb_interval: float = 15.0
    last_agent_seq:  int = 0
    events:          deque = field(default_factory=lambda: deque(maxlen=MAX_EVENTS_PER_VM))
    scored_events:   deque = field(default_factory=lambda: deque(maxlen=MAX_EVENTS_PER_VM))
    ir_log:          List[dict] = field(default_factory=list)
    heartbeat_count: int = 0
    last_decision:   dict = field(default_factory=dict)   # explainable decision (non-AI)

    def purge_expired(self, now: float):
        cutoff = now - ROLLING_WINDOW_SECS
        while self.scored_events and self.scored_events[0].timestamp < cutoff:
            self.scored_events.popleft()

    def recalculate_score(self) -> int:
        now = time.time()
        self.purge_expired(now)
        total = sum(e.score_delta for e in self.scored_events)
        self.threat_score = min(total, 200)   # allow >100 so severity is meaningful
        if self.isolated:
            self.status = "ISOLATED" if self.isolation_enforced else "QUARANTINE_UNENFORCED"
        elif self.threat_score >= ISOLATION_THRESHOLD:
            self.status = "CRITICAL"
        elif self.threat_score >= 50:
            self.status = "WARNING"
        else:
            self.status = "SECURE"
        return self.threat_score

    def to_dict(self) -> dict:
        return {
            "vm_id": self.vm_id,
            "threat_score": self.threat_score,
            "status": self.status,
            "isolated": self.isolated,
            "isolation_enforced": self.isolation_enforced,
            "isolation_detail": self.isolation_detail,
            "silent": self.silent,
            "last_seen": self.last_seen,
            "heartbeat_count": self.heartbeat_count,
            "decision": self.last_decision,   # explainable, deterministic response decision
            "event_count": len(self.events),
            "recent_events": [
                {"timestamp": e.raw_event.get("timestamp"), "event_type": e.event_type,
                 "severity": e.severity, "score_delta": e.score_delta, "details": e.details}
                for e in list(self.events)[-20:]
            ],
            "ir_log": self.ir_log[-12:],
        }


# ---------------------------------------------------------------------------
# Correlation Engine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    def __init__(self, hypervisor: HypervisorAPI, failover: FailoverOrchestrator,
                 containment=None):
        self.hypervisor = hypervisor
        self.failover = failover
        # Optional host-network containment backend (dry-run by default). This is
        # the OS-level NIC block that runs *alongside* the hypervisor isolation —
        # it cuts C2/exfil even before the hypervisor path completes. If None, we
        # lazily build a dry-run backend so the control plane is always safe.
        if containment is None:
            try:
                from containment import build_backend
                containment = build_backend(dry_run=True)
            except Exception:
                containment = None
        self.containment = containment
        self._lock = threading.Lock()
        self._vms: Dict[str, VMState] = {}
        self._isolation_queue: deque = deque()
        self._block_queue: deque = deque()       # instant hard-blocks (crypto spike)
        self._failover_count = 0
        self._seen_techniques: set = set()        # MITRE ATT&CK technique IDs observed
        self.alerts = AlertManager()              # SOC triage workflow
        # SIEM forwarding (CEF / ECS-JSON / RFC5424). Returns None unless
        # EXONERVE_SIEM_FILE or EXONERVE_SIEM_COLLECTOR is configured, so
        # this is strictly opt-in and adds no default runtime cost.
        self.siem = exporter_from_env()
        # On-call paging (CEF/ECS/syslog above gets alerts into a log
        # pipeline; nothing in that path pages a human). Same opt-in
        # posture: None unless EXONERVE_PAGERDUTY_ROUTING_KEY or
        # EXONERVE_TICKETING_WEBHOOK_URL is configured.
        self.ticketing = ticketing_from_env()
        # Incident case management (v3.11) — correlates raised alerts into
        # lifecycle-tracked cases. Always on; unlike SIEM/ticketing this has
        # no external dependency to opt into.
        self.incidents = IncidentManager()
        # Re-pages an alert that's sat OPEN (never acknowledged) past
        # ESCALATE_AFTER_S. No-ops cleanly if ticketing isn't configured.
        self.escalation = EscalationPolicy(self.alerts, self.ticketing,
                                           escalate_after_s=ESCALATE_AFTER_S)
        self._playbooks: Dict[str, "Playbook"] = {}   # incident_id -> Playbook, lazily created
        self.decisions = DecisionEngine()         # explainable, deterministic response decisions
        self._geo_events: deque = deque(maxlen=200)  # enriched destination IPs for the map
        # Tamper-evident, append-only DFIR audit trail for every decision/action.
        try:
            from audit_log import DecisionAuditLog
        except ImportError:
            from common.audit_log import DecisionAuditLog
        self.audit = DecisionAuditLog()
        self._last_logged_verdict: Dict[str, str] = {}  # de-dupe repeated verdicts

    def get_or_create_vm(self, vm_id: str) -> VMState:
        with self._lock:
            if vm_id not in self._vms:
                self._vms[vm_id] = VMState(vm_id=vm_id)
            return self._vms[vm_id]

    @staticmethod
    def _safe_vm_id(raw) -> str:
        """Constrain vm_id to a safe charset at the boundary. Agent-supplied
        identifiers must never carry markup or control chars — this protects
        every downstream context (dashboard DOM, logs, DOM ids) at the source,
        independent of client-side escaping."""
        vid = str(raw or "unknown")
        # keep only hostname-ish characters; collapse anything else
        cleaned = re.sub(r"[^A-Za-z0-9._-]", "", vid)[:64]
        return cleaned or "unknown"

    def process_batch(self, payload: dict):
        vm_id = self._safe_vm_id(payload.get("vm_id", "unknown"))
        events = payload.get("batch", [])
        vm = self.get_or_create_vm(vm_id)
        with self._lock:
            vm.last_seen = time.time()
            vm.silent = False
            for raw in events:
                et = raw.get("event_type", "unknown")
                sev = raw.get("severity", "low")
                details = raw.get("details", {})
                if et == "heartbeat":
                    vm.heartbeat_count += 1
                    vm.last_hb_interval = float(details.get("interval_s", vm.last_hb_interval))
                    vm.last_agent_seq = int(details.get("agent_seq", vm.last_agent_seq))
                    continue
                delta = _resolve_delta(et, details)   # authoritative, not agent-supplied
                # Tag the event with its MITRE ATT&CK technique(s).
                techs = map_event_to_techniques(et, details)
                if techs:
                    details = dict(details)
                    details["attack"] = [{"id": t.tid, "name": t.name} for t in techs]
                    for t in techs:
                        self._seen_techniques.add(t.tid)
                se = ScoredEvent(time.time(), et, sev, delta, details, raw)
                vm.scored_events.append(se)
                vm.events.append(se)
                # Raise a triage alert for meaningful events.
                alert = self.alerts.raise_alert(vm_id, et, sev, delta, details,
                                                event_ts_iso=raw.get("timestamp"))
                # Correlate into a case (v3.11). Same wrapped posture as
                # ticketing/SIEM below — a bug in case correlation must never
                # be able to break detection, scoring, or containment, which
                # all already happened above this point.
                if alert and self.incidents:
                    try:
                        self.incidents.ingest_alert(alert)
                    except Exception:
                        pass
                # Page on-call. Gated on an actual Alert being raised (already
                # deduped, already above ALERT_MIN_DELTA) rather than on every
                # event — a ticketing/paging integration that fires on
                # low-signal events is worse than none; it trains the on-call
                # rotation to ignore it. Wrapped for the same reason as SIEM
                # forwarding below: a broken ticketing endpoint must never be
                # able to break detection or containment.
                if alert and self.ticketing:
                    try:
                        self.ticketing.emit({
                            "vm_id": vm_id, "event_type": et, "severity": sev,
                            "score": delta, "details": details,
                            "timestamp": raw.get("timestamp"),
                            "techniques": details.get("attack", []),
                            "title": alert.title,
                        })
                    except Exception:
                        pass
                # Forward to the SOC's existing SIEM. Wrapped because export
                # must never be able to break detection or containment.
                if self.siem:
                    try:
                        self.siem.emit({
                            "vm_id": vm_id, "event_type": et, "severity": sev,
                            "score": delta, "details": details,
                            "timestamp": raw.get("timestamp"),
                            "timestamp_epoch": time.time(),
                            "techniques": details.get("attack", []),
                            "title": details.get("reason", et),
                        })
                    except Exception:
                        pass
                # Enrich destination IPs for the live attack map + intel panel.
                if et == "network":
                    dip = details.get("dest_ip")
                    if dip:
                        enriched = enrich_ip(dip)
                        enriched.update({"vm_id": vm_id, "dest_port": details.get("dest_port"),
                                         "ts": time.time()})
                        self._geo_events.append(enriched)
                if et in INSTANT_BLOCK_TYPES and not vm.isolated:
                    self._block_queue.append(vm_id)
            score = vm.recalculate_score()
            # --- Deterministic decision (non-AI): decide the response and record
            #     the full explanation so the dashboard shows *why*, not a black box.
            has_standby = False
            try:
                has_standby = bool(getattr(self.failover, "has_standby", lambda _v: False)(vm_id))
            except Exception:
                has_standby = False
            # Use the HIGHEST actual event severity seen in the rolling window — a
            # score-derived severity would mask a single critical reflex signal.
            _rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
            recent = list(vm.scored_events)[-25:]
            top_ev = max(recent, key=lambda e: _rank.get(e.severity, 0), default=None)
            top_sev = top_ev.severity if top_ev else "low"
            fact = Fact(event_type=(top_ev.event_type if top_ev else "none"),
                        severity=top_sev, score=score,
                        techniques=sorted(self._seen_techniques),
                        has_standby=has_standby)
            decision = self.decisions.decide(fact)
            vm.last_decision = {**decision.to_dict(), "explanation": decision.explain()}
            # DFIR: write every *change* in verdict to the tamper-evident log,
            # with the exact inputs and human-readable reason that produced it.
            verdict = decision.to_dict().get("verdict", "monitor")
            if self._last_logged_verdict.get(vm_id) != verdict:
                self._last_logged_verdict[vm_id] = verdict
                try:
                    self.audit.record(
                        verdict=verdict.upper(), vm_id=vm_id,
                        reason=decision.explain(),
                        data={"score": score, "top_severity": top_sev,
                              "techniques": sorted(self._seen_techniques)})
                except Exception as exc:
                    logger.error("audit log write failed: %s", exc)
            if score >= ISOLATION_THRESHOLD and not vm.isolated:
                logger.critical("[ALERT] VM %s reached threat score %d - queuing isolation", vm_id, score)
                self._isolation_queue.append(vm_id)

    # ---- queue draining (called from worker thread) ----------------------

    def drain_queues(self):
        while self._block_queue:
            vm_id = self._block_queue.popleft()
            self._instant_block(vm_id)
        while self._isolation_queue:
            vm_id = self._isolation_queue.popleft()
            self._trigger_isolation(vm_id, reason="auto")

    def _instant_block(self, vm_id: str):
        """Immediate NIC kill-switch on a ransomware crypto-spike, ahead of full IR."""
        vm = self.get_or_create_vm(vm_id)
        with self._lock:
            if vm.isolated:
                return
        logger.critical("[CRYPTO-SPIKE] Hard-blocking network for %s before full IR", vm_id)
        r = self.hypervisor.block_network(vm_id)
        with self._lock:
            vm.ir_log.append({"timestamp": r.timestamp, "operation": "block_network",
                              "success": r.success, "message": r.message})
        # Host-level containment (iptables/nftables/netsh/pf) in parallel with the
        # hypervisor block. Dry-run by default; records the exact rules it would apply.
        if self.containment is not None:
            try:
                actions = self.containment.isolate_host()
                applied = "applied" if not self.containment.dry_run else "dry-run"
                with self._lock:
                    vm.ir_log.append({
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "operation": f"host_containment ({self.containment.name}, {applied})",
                        "success": True,
                        "message": f"{len(actions)} firewall rule(s) staged to cut C2/exfil"})
            except Exception as exc:
                logger.error("host containment failed: %s", exc)

    def _trigger_isolation(self, vm_id: str, reason: str = "auto"):
        vm = self.get_or_create_vm(vm_id)
        with self._lock:
            if vm.isolated:
                return
            vm.isolated = True   # the system has DECIDED to isolate (logical intent)
        logger.critical("[ISOLATION] Full IR + continuity failover for %s (reason=%s)", vm_id, reason)

        # 1-3 + 5-6: hypervisor incident response (isolate, dump, restore, boot).
        results = self.hypervisor.full_incident_response(vm_id)
        # Did NETWORK isolation actually succeed? That is the operation that truly
        # contains the VM. We report the honest truth, not a hopeful "ISOLATED".
        net_ok = any(r.success for r in results
                     if r.operation in ("isolate_network", "block_network"))
        steps_ok = sum(1 for r in results if r.success)
        with self._lock:
            for r in results:
                vm.ir_log.append({"timestamp": r.timestamp, "operation": r.operation,
                                  "success": r.success, "message": r.message})

        # Host-level containment (iptables/nftables/netsh/pf). Only counts as REAL
        # enforcement when it actually applied rules (not dry-run).
        host_ok = False
        if self.containment is not None and not getattr(self.containment, "dry_run", True):
            try:
                self.containment.isolate_host()
                host_ok = True
            except Exception as exc:
                logger.error("host containment failed: %s", exc)

        enforced = bool(net_ok or host_ok)
        with self._lock:
            vm.isolation_enforced = enforced
            if enforced:
                vm.status = "ISOLATED"
                vm.isolation_detail = (f"Network contained ({steps_ok}/{len(results)} "
                                       f"hypervisor steps OK).")
            else:
                # Honest: the decision was made, but nothing on this host could
                # actually cut the VM's network (no hypervisor/root backend present).
                vm.status = "QUARANTINE_UNENFORCED"
                vm.isolation_detail = (
                    "DECISION ONLY — no hypervisor/host backend enforced the block "
                    "on this machine (e.g. VBoxManage/virsh/root iptables absent). "
                    "Detection + decision are real; network cut requires a VM/hypervisor host.")
                logger.warning("[ISOLATION] %s: decision made but NOT enforced (%s)",
                               vm_id, vm.isolation_detail)

        # Business-continuity failover so the workload keeps running.
        fo = self.failover.handle_compromise(vm_id)
        with self._lock:
            if fo is not None:
                self._failover_count += 1
                vm.ir_log.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "operation": "failover",
                    "success": fo["state"] in ("DEGRADED", "RESTORED", "HEALTHY"),
                    "message": (f"Service '{fo['service']}' -> {fo['state']} "
                                f"(active={fo['active_node']}, RTO={fo.get('rto_seconds')}s)"),
                })

    def manual_isolate(self, vm_id: str) -> dict:
        threading.Thread(target=self._trigger_isolation, args=(vm_id, "manual"),
                         daemon=True).start()
        return {"status": "ok", "message": f"Isolation + failover triggered for {vm_id}"}

    def abort_and_restore(self, vm_id: str) -> dict:
        vm = self.get_or_create_vm(vm_id)
        with self._lock:
            vm.scored_events.clear()
            vm.events.clear()
            vm.threat_score = 0
            vm.isolated = False
            vm.isolation_enforced = False
            vm.isolation_detail = ""
            vm.silent = False
            vm.status = "SECURE"
            vm.ir_log.append({"timestamp": datetime.now(timezone.utc).isoformat(),
                              "operation": "abort_and_restore", "success": True,
                              "message": "Threat score reset by operator"})
        svc = self.failover.service_for_vm(vm_id)
        if svc:
            self.failover.reset_service(svc)
        logger.info("[MANUAL] Abort & restore executed for VM: %s", vm_id)
        return {"status": "ok", "message": f"Threat score cleared for {vm_id}"}

    def get_or_create_playbook(self, incident_id: str) -> Optional["Playbook"]:
        """Lazily creates the incident's playbook on first access, wired to
        real hypervisor actions via make_default_playbook — same
        already-tested block_network() call the rest of this engine uses,
        not a new implementation of containment.

        backdoor_check is deliberately left unwired here: BackdoorCheck
        inspects the LOCAL filesystem/process list of whatever machine runs
        it. This method executes on the control-plane host, which is a
        DIFFERENT machine from the compromised guest VM in this project's
        out-of-band architecture — wiring it here would silently check the
        control plane's own OS state instead of the VM's, which is wrong,
        not just incomplete. A correct integration needs BackdoorCheck
        invoked IN the guest's context (e.g. a guest-agent command
        triggered over the existing telemetry tunnel, reporting results
        back) — that remote-invocation path does not exist yet and is
        tracked as an open item rather than papered over with an
        incorrect local instantiation.
        """
        if incident_id in self._playbooks:
            return self._playbooks[incident_id]
        incident = self.incidents.get_incident(incident_id)
        if incident is None:
            return None
        pb = make_default_playbook(incident_id, incident.vm_id, self.incidents,
                                   self.hypervisor)
        pb.capture_baseline()
        self._playbooks[incident_id] = pb
        return pb

    # ---- watchdog --------------------------------------------------------

    def watchdog_sweep(self):
        """Flag agents that went silent past their grace window. Aggressive posture:
        unexplained silence on a non-isolated VM raises a synthetic alert."""
        now = time.time()
        with self._lock:
            for vm in self._vms.values():
                if vm.last_seen == 0 or vm.isolated:
                    continue
                gap = now - vm.last_seen
                grace = vm.last_hb_interval * SILENCE_GRACE_MULTIPLIER
                if gap > grace and not vm.silent:
                    vm.silent = True
                    logger.warning("[WATCHDOG] Agent on %s silent for %.0fs (>%.0fs grace) "
                                   "- possible agent kill", vm.vm_id, gap, grace)
                    se = ScoredEvent(now, "agent_silence", "high",
                                     SCORE_WEIGHTS["agent_silence"],
                                     {"reason": "agent_silence",
                                      "silent_seconds": round(gap, 1),
                                      "message": f"Agent silent {gap:.0f}s — possible tamper"},
                                     {"timestamp": datetime.now(timezone.utc).isoformat(),
                                      "event_type": "agent_silence"})
                    vm.scored_events.append(se)   # contributes to threat score
                    vm.events.append(se)
                    self._seen_techniques.add("T1562.001")  # Impair Defenses
                    if vm.recalculate_score() >= ISOLATION_THRESHOLD and not vm.isolated:
                        self._isolation_queue.append(vm.vm_id)

    def get_all_vm_states(self) -> List[dict]:
        with self._lock:
            for vm in self._vms.values():
                vm.recalculate_score()
            return [vm.to_dict() for vm in self._vms.values()]

    def stats(self) -> dict:
        with self._lock:
            return {"failover_count": self._failover_count}

    def get_geo_events(self) -> List[dict]:
        with self._lock:
            return list(self._geo_events)[-60:]


# ---------------------------------------------------------------------------
# Telemetry server (authenticated)
# ---------------------------------------------------------------------------

def recv_framed(conn) -> Optional[bytes]:
    try:
        header = _recv_exact(conn, 4)
        if not header:
            return None
        length = struct.unpack(">I", header)[0]
        if length > 10 * 1024 * 1024:
            logger.warning("Frame too large (%d bytes), dropping", length)
            return None
        return _recv_exact(conn, length)
    except Exception as exc:
        logger.debug("recv_framed dropped a frame: %s: %s", exc.__class__.__name__, exc)
        return None


def _recv_exact(conn, n: int) -> Optional[bytes]:
    buf = b""
    while len(buf) < n:
        try:
            chunk = conn.recv(n - len(buf))
        except Exception:
            return None
        if not chunk:
            return None
        buf += chunk
    return buf


class TelemetryHandler(socketserver.BaseRequestHandler):
    def handle(self):
        conn = self.request
        peer = self.client_address
        engine: CorrelationEngine = self.server.engine
        receiver: SecureReceiver = self.server.receiver
        raw = recv_framed(conn)
        if raw is None:
            return
        try:
            agent_id, payload = receiver.open(raw)   # auth + replay + identity binding
        except AuthError as e:
            logger.warning("[SECURITY] Rejected frame from %s: %s", peer[0], e)
            return
        except Exception as e:
            logger.warning("Failed to parse frame from %s: %s", peer[0], e)
            return
        engine.process_batch(payload)
        logger.debug("Accepted %d events from authenticated agent '%s' (%s)",
                     len(payload.get("batch", [])), agent_id, peer[0])


class TelemetryServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, host, port, engine, receiver):
        self.engine = engine
        self.receiver = receiver
        super().__init__((host, port), TelemetryHandler)


# ---------------------------------------------------------------------------
# Flask app
# ---------------------------------------------------------------------------

_DASHBOARD_HTML = (Path(__file__).parent / "dashboard.html").read_text(encoding="utf-8")


def _const_eq(a: str, b: str) -> bool:
    """Constant-time string comparison to avoid token timing leaks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _is_dev_master_key(master: bytes) -> bool:
    """True if the loaded master secret is the public development fallback."""
    import hashlib
    dev = hashlib.sha256(b"exonerve-development-master-key-CHANGE-ME").digest()
    return hmac.compare_digest(master, dev)


def create_flask_app(engine: CorrelationEngine, api_token: str,
                     allowed_ips: Optional[set] = None) -> Flask:
    from flask import request, abort

    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.urandom(32)

    # Endpoints that change state require the API token. Read-only status and the
    # dashboard HTML stay open so the UI loads, but every mutation is gated.
    _PROTECTED_PREFIXES = ("/api/isolate", "/api/restore")

    def _is_protected(path: str, method: str) -> bool:
        if method not in ("POST", "PUT", "DELETE", "PATCH"):
            return False
        if path.startswith(_PROTECTED_PREFIXES):
            return True
        if path.startswith("/api/alerts/"):
            return True
        if path.startswith("/api/incidents/"):
            return True
        return False

    @app.before_request
    def _guard():
        # 1) Optional IP allowlist (applies to everything).
        if allowed_ips is not None and request.remote_addr not in allowed_ips:
            logger.warning("[SECURITY] Blocked request from %s (not in allowlist)",
                           request.remote_addr)
            abort(403)
        # 2) Token required for state-changing endpoints — EXCEPT from localhost,
        #    which is already trusted (anyone on the box can run commands directly).
        #    This makes the local demo frictionless while keeping remote calls gated.
        if _is_protected(request.path, request.method):
            if request.remote_addr in ("127.0.0.1", "::1", "localhost"):
                return  # local operator is trusted
            supplied = (request.headers.get("X-Exonerve-Token")
                        or request.headers.get("Authorization", "").replace("Bearer ", "").strip())
            if not supplied or not _const_eq(supplied, api_token):
                logger.warning("[SECURITY] Rejected unauthenticated %s %s from %s",
                               request.method, request.path, request.remote_addr)
                abort(401)

    # Return JSON (not Flask's HTML error page) so the dashboard's fetch()/JSON
    # parsing never chokes with "Unexpected token '<'". The UI can show a clean
    # message instead of crashing its poll loop.
    @app.errorhandler(401)
    def _json_401(e):
        return jsonify({"ok": False, "error": "unauthorized",
                        "message": "API token required for this action (remote caller)."}), 401

    @app.errorhandler(403)
    def _json_403(e):
        return jsonify({"ok": False, "error": "forbidden",
                        "message": "Your IP is not in the allowlist."}), 403

    # Serve the dashboard as a static page. The API token is NOT embedded here:
    # the operator supplies it in the browser (prompted once, kept in sessionStorage)
    # so that merely loading the page grants no ability to call protected endpoints.
    # Rendered as a plain Response (no Jinja) to avoid any server-side template
    # injection surface if page content ever becomes dynamic.
    @app.route("/")
    def dashboard():
        resp = Response(_DASHBOARD_HTML, mimetype="text/html")
        # Defense-in-depth against XSS: the dashboard uses no external scripts,
        # so a strict CSP blocks any injected <script>/inline handler from
        # loading or exfiltrating. 'unsafe-inline' is required only for the
        # single inline <script>/<style> block this page ships.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; "
            "frame-ancestors 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        return resp

    @app.route("/api/status")
    def api_status():
        return jsonify({
            "vms": engine.get_all_vm_states(),
            "failover": engine.failover.get_all(),
            "attack_matrix": matrix_state(engine._seen_techniques),
            "alerts": engine.alerts.get_alerts(50),
            "alert_metrics": engine.alerts.metrics(),
            "incidents": engine.incidents.list_incidents(),
            "geo_events": engine.get_geo_events(),
            "stats": engine.stats(),
            "server_time": datetime.now(timezone.utc).isoformat(),
        })

    @app.route("/api/stix")
    def api_stix():
        # Download a STIX 2.1 bundle of detection content for import into any
        # STIX/TAXII-aware platform (OpenCTI, MISP, Sentinel, TheHive).
        try:
            from stix_export import build_bundle
        except ImportError:
            from common.stix_export import build_bundle
        # scope to live-observed techniques if requested, else full coverage
        if request.args.get("mode") == "live":
            bundle = build_bundle(technique_ids=sorted(engine._seen_techniques))
        else:
            bundle = build_bundle()
        resp = jsonify(bundle)
        resp.headers["Content-Disposition"] = "attachment; filename=exonerve_detections.stix.json"
        return resp

    @app.route("/api/attack-layer")
    def api_attack_layer():
        # Download a MITRE ATT&CK Navigator layer of live coverage. Load the
        # returned JSON at mitre-attack.github.io/attack-navigator to see the
        # engagement painted on the real ATT&CK matrix.
        try:
            from attack_navigator import live_layer, coverage_layer
        except ImportError:
            from common.attack_navigator import live_layer, coverage_layer
        mode = request.args.get("mode", "live")
        if mode == "coverage":
            layer = coverage_layer()
        else:
            counts = {}
            for tid in engine._seen_techniques:
                counts[tid] = counts.get(tid, 0) + 1
            layer = live_layer(counts)
        resp = jsonify(layer)
        resp.headers["Content-Disposition"] = f"attachment; filename=exonerve_{mode}_layer.json"
        return resp

    @app.route("/api/audit")
    def api_audit():
        # Read-only DFIR view: the decision trail + a live integrity check that
        # proves the log hasn't been tampered with since it was written.
        try:
            from audit_log import read_entries
        except ImportError:
            from common.audit_log import read_entries
        entries = read_entries(engine.audit.path)
        return jsonify({
            "entries": entries[-200:],
            "count": len(entries),
            "signed": engine.audit.signed,
            "integrity": engine.audit.verify(),
        })

    @app.route("/api/alerts/<alert_id>/<action>", methods=["POST"])
    def api_alert_action(alert_id, action):
        body = request.get_json(silent=True) or {}
        by = body.get("by", "analyst")
        if action == "ack":
            return jsonify(engine.alerts.acknowledge(alert_id, by))
        if action == "assign":
            return jsonify(engine.alerts.assign(alert_id, body.get("assignee", "tier1"), by))
        if action == "escalate":
            return jsonify(engine.alerts.escalate(alert_id, by))
        if action == "close":
            return jsonify(engine.alerts.close(alert_id, by, body.get("note", "")))
        if action == "false_positive":
            return jsonify(engine.alerts.mark_false_positive(alert_id, by, body.get("note", "")))
        if action == "note":
            return jsonify(engine.alerts.add_note(alert_id, body.get("text", ""), by))
        return jsonify({"ok": False, "message": f"unknown action '{action}'"}), 400

    @app.route("/api/incidents")
    def api_incidents_list():
        # Case view on top of /api/alerts: related alerts on one VM grouped
        # into a lifecycle-tracked incident (v3.11). Optional ?status= and
        # ?vm_id= filters, same query-param style as the rest of this API.
        status_arg = request.args.get("status")
        status = None
        if status_arg:
            try:
                status = IncidentStatus(status_arg.upper())
            except ValueError:
                return jsonify({"ok": False, "message": f"unknown status '{status_arg}'"}), 400
        return jsonify({"incidents": engine.incidents.list_incidents(
            status=status, vm_id=request.args.get("vm_id"))})

    @app.route("/api/incidents/<incident_id>")
    def api_incident_detail(incident_id):
        incident = engine.incidents.get_incident(incident_id)
        if incident is None:
            return jsonify({"ok": False, "message": "incident not found"}), 404
        return jsonify(incident.to_dict())

    @app.route("/api/incidents/<incident_id>/<action>", methods=["POST"])
    def api_incident_action(incident_id, action):
        body = request.get_json(silent=True) or {}
        by = body.get("by", "analyst")
        if action == "report":
            # On-demand post-incident report (v3.11, Priority 3): stitches
            # together the kill-chain reconstruction, ATT&CK Navigator layer,
            # and STIX bundle for just this incident's techniques, plus this
            # VM's recorded containment/failover action log.
            incident = engine.incidents.get_incident(incident_id)
            if incident is None:
                return jsonify({"ok": False, "message": "incident not found"}), 404
            vm = engine._vms.get(incident.vm_id)
            out_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "forensics_archive", "incident_reports", incident_id)
            try:
                ir_log = vm.ir_log if vm else []
                result = engine.incidents.generate_report(incident_id, out_dir, ir_log=ir_log)
            except ValueError as exc:
                return jsonify({"ok": False, "message": str(exc)}), 404
            with open(result["markdown_path"], encoding="utf-8") as f:
                markdown = f.read()
            return jsonify({"ok": True, "incident_id": incident_id, "markdown": markdown,
                            "kill_chain": result["kill_chain"],
                            "navigator_layer_path": result["navigator_layer_path"],
                            "stix_bundle_path": result["stix_bundle_path"]})
        try:
            new_status = IncidentStatus(action.upper())
        except ValueError:
            return jsonify({"ok": False, "message": f"unknown action/status '{action}'"}), 400
        return jsonify(engine.incidents.transition(incident_id, new_status, by,
                                                   body.get("note", "")))

    @app.route("/api/incidents/<incident_id>/playbook")
    def api_playbook_status(incident_id):
        pb = engine.get_or_create_playbook(incident_id)
        if pb is None:
            return jsonify({"ok": False, "message": "incident not found"}), 404
        return jsonify(pb.to_dict())

    @app.route("/api/incidents/<incident_id>/playbook/<pb_action>", methods=["POST"])
    def api_playbook_action(incident_id, pb_action):
        """The HITL gates: advance auto-executes the fast/reversible
        stages; every other action here corresponds to an explicit SOC
        decision and is rejected by Playbook itself if called out of
        order (see playbook.py's _wrong_stage_error) — this route is thin
        dispatch, not where that safety property lives."""
        pb = engine.get_or_create_playbook(incident_id)
        if pb is None:
            return jsonify({"ok": False, "message": "incident not found"}), 404
        body = request.get_json(silent=True) or {}
        by = body.get("by", "analyst")

        if pb_action == "advance":
            return jsonify(pb.advance_auto())
        if pb_action == "vuln_scan":
            return jsonify(pb.trigger_vuln_scan(body.get("findings", []), by))
        if pb_action == "approve_remediation":
            return jsonify(pb.approve_remediation(by, body.get("note", "")))
        if pb_action == "approve_backdoor_check":
            return jsonify(pb.approve_backdoor_check(by, body.get("note", "")))
        if pb_action == "revalidate":
            return jsonify(pb.complete_revalidation(body.get("findings", []), by))
        if pb_action == "close":
            return jsonify(pb.close(by, body.get("note", "")))
        if pb_action == "reopen":
            try:
                target = PlaybookStage(body.get("stage", "").upper())
            except ValueError:
                return jsonify({"ok": False,
                               "message": f"unknown stage '{body.get('stage')}'"}), 400
            return jsonify(pb.reopen_to(target, by, body.get("reason", "")))
        return jsonify({"ok": False, "message": f"unknown playbook action '{pb_action}'"}), 400

    @app.route("/api/isolate/<vm_id>", methods=["POST"])
    def api_isolate(vm_id):
        return jsonify(engine.manual_isolate(vm_id))

    @app.route("/api/restore/<vm_id>", methods=["POST"])
    def api_restore(vm_id):
        return jsonify(engine.abort_and_restore(vm_id))

    @app.route("/healthz")
    def healthz():
        return jsonify({"status": "ok", "service": "exonerve-control-center"})

    return app


# ---------------------------------------------------------------------------
# Demo topology (registers HA service pairs so failover has something to do)
# ---------------------------------------------------------------------------

def register_demo_topology(failover: FailoverOrchestrator):
    """Register sensible defaults so the failover panel is populated out-of-box.
    In production, drive this from hypervisor_config.json instead."""
    failover.register_service("web-app", "10.0.0.100", "test-vm-01", ["test-vm-02"])
    failover.register_service("db", "10.0.0.110", "prod-vm-01", ["prod-vm-02"])


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    p = argparse.ArgumentParser(description="Exonerve Control Center v2")
    # bandit flags these as B104 (bind-all-interfaces). Deliberately NOT
    # changed to 127.0.0.1 by default: this control plane's web UI and
    # telemetry listener are commonly reached from other hosts on the
    # deployment's own network (analysts' browsers, guest agents on
    # separate VMs) — silently narrowing the default here without knowing
    # the actual deployment topology risks breaking real, working setups
    # rather than fixing anything. State-changing API routes already
    # require the API token for any non-localhost caller (see
    # `_is_protected`/`_guard` above); read-only routes and the dashboard
    # do not, which is the actual thing to restrict via firewall/security-
    # group rules or by passing --listen-host/--web-host explicitly if this
    # deployment doesn't need broad network reachability. Named here, not
    # silently suppressed. See DEFENSE_GUIDE.md's Open Items.
    p.add_argument("--listen-host", default="0.0.0.0")  # nosec B104
    p.add_argument("--listen-port", type=int, default=9999)
    p.add_argument("--web-host", default="0.0.0.0")  # nosec B104
    p.add_argument("--web-port", type=int, default=5000)
    p.add_argument("--hypervisor-config", default=None)
    p.add_argument("--key-file", default=None, help="Master key file (else env EXONERVE_MASTER_KEY or dev key)")
    p.add_argument("--max-skew", type=float, default=120.0, help="Max telemetry timestamp skew (s)")
    p.add_argument("--api-token", default=None,
                   help="Bearer token required for state-changing API calls "
                        "(default: env EXONERVE_API_TOKEN, else an auto-generated token printed at startup)")
    p.add_argument("--allow-ips", default=None,
                   help="Comma-separated IP allowlist for the dashboard/API (default: allow any)")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = p.parse_args()

    logging.getLogger().setLevel(getattr(logging, args.log_level))

    hyp = HypervisorAPI(load_default_config(args.hypervisor_config))
    failover = FailoverOrchestrator(SimulatedBackend())
    register_demo_topology(failover)
    engine = CorrelationEngine(hyp, failover)
    master = load_master_secret(fallback_file=args.key_file)
    receiver = SecureReceiver(master, max_skew=args.max_skew)

    # --- Security: loud warning if the public development key is in use ---
    if _is_dev_master_key(master):
        logger.warning("=" * 70)
        logger.warning("[SECURITY] Using the PUBLIC development master key.")
        logger.warning("[SECURITY] Telemetry can be FORGED by anyone who has read the source.")
        logger.warning("[SECURITY] Set EXONERVE_MASTER_KEY (hex) before any real deployment.")
        logger.warning("=" * 70)

    # --- Security: API token for state-changing endpoints ---
    api_token = args.api_token or os.environ.get("EXONERVE_API_TOKEN")
    if not api_token:
        api_token = secrets.token_urlsafe(24)
        logger.warning("[SECURITY] No --api-token / EXONERVE_API_TOKEN set; generated one for this session:")
        logger.warning("[SECURITY]   API token: %s", api_token)
        logger.warning("[SECURITY]   (localhost actions work without it; REMOTE callers must send this token)")

    allowed_ips = None
    if args.allow_ips:
        allowed_ips = {ip.strip() for ip in args.allow_ips.split(",") if ip.strip()}
        logger.info("[SECURITY] Dashboard/API restricted to IPs: %s", sorted(allowed_ips))

    app = create_flask_app(engine, api_token=api_token, allowed_ips=allowed_ips)

    tcp = TelemetryServer(args.listen_host, args.listen_port, engine, receiver)
    threading.Thread(target=tcp.serve_forever, name="TelemetryServer", daemon=True).start()
    logger.info("Telemetry listener (authenticated) on %s:%d", args.listen_host, args.listen_port)

    logging.getLogger("werkzeug").setLevel(logging.WARNING)
    threading.Thread(target=lambda: app.run(host=args.web_host, port=args.web_port,
                                            debug=False, use_reloader=False, threaded=True),
                     name="FlaskSOC", daemon=True).start()
    logger.info("SOC Dashboard on http://%s:%d", args.web_host, args.web_port)
    if args.web_host not in ("127.0.0.1", "localhost", "::1"):
        logger.warning("[SECURITY] Dashboard bound to %s (not localhost). /api/status "
                       "is READ-ONLY but UNAUTHENTICATED — it exposes VM state, alerts "
                       "and IR telemetry to anyone who can reach this port. Use "
                       "--web-host 127.0.0.1 for local-only, or --allow-ips to restrict.",
                       args.web_host)
    logger.info("Exonerve Control Center v2 running. Threshold=%d / %ds window.",
                ISOLATION_THRESHOLD, ROLLING_WINDOW_SECS)

    last_watchdog = 0.0
    last_escalation_check = 0.0
    try:
        while True:
            engine.drain_queues()
            now = time.time()
            if now - last_watchdog > 5.0:
                engine.watchdog_sweep()
                last_watchdog = now
            if now - last_escalation_check > 60.0:
                try:
                    escalated = engine.escalation.check_and_escalate()
                    if escalated:
                        logger.warning("Escalated %d unacknowledged alert(s): %s",
                                       len(escalated), escalated)
                except Exception as exc:
                    logger.error("Escalation check failed (non-fatal): %s", exc)
                last_escalation_check = now
            time.sleep(0.3)
    except KeyboardInterrupt:
        logger.info("Shutting down Control Center.")
        tcp.shutdown()


if __name__ == "__main__":
    main()
