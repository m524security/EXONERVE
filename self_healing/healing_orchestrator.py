#!/usr/bin/env python3
"""
Exonerve :: Healing Orchestrator (repair + homeostatic recovery)
====================================================================
The "regeneration" layer. When the health monitor reports a component out of
its healthy range, the orchestrator runs a control loop that drives the system
back toward its desired state — like a body healing a wound.

Three classic, proven self-healing mechanisms:

  1. DESIRED-STATE RECONCILIATION  — compare desired vs actual, emit the
     corrective action (the same idea Kubernetes uses; the same idea homeostasis
     uses). Idempotent: safe to run every tick.
  2. CIRCUIT BREAKER               — a component that keeps failing is tripped
     OPEN so its failures stop cascading; after a cool-down it goes HALF-OPEN to
     probe recovery, then CLOSED when healthy again.
  3. REMEDIATION PLAYBOOKS         — symptom -> cure, with exponential backoff +
     jitter and a hard cap that ESCALATES TO A HUMAN (never loops forever).

All actions are dry-run by default (they emit intent through the bus); wire the
callbacks to real effectors in production.
"""
from __future__ import annotations

import random
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

from .health_monitor import HealthMonitor, HealthState
from .nervous_system import EfferentCommand, NervousSystem, SignalKind


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class BreakerState(str, Enum):
    CLOSED = "closed"        # healthy, traffic flows
    OPEN = "open"            # tripped, failing fast to prevent cascade
    HALF_OPEN = "half_open"  # probing whether recovery happened


@dataclass
class CircuitBreaker:
    name: str
    fail_threshold: int = 3
    cooldown_s: float = 10.0
    failures: int = 0
    state: BreakerState = BreakerState.CLOSED
    opened_at: float = 0.0

    def record_failure(self) -> BreakerState:
        self.failures += 1
        if self.failures >= self.fail_threshold and self.state == BreakerState.CLOSED:
            self.state = BreakerState.OPEN
            self.opened_at = time.time()
        return self.state

    def record_success(self) -> BreakerState:
        self.failures = 0
        self.state = BreakerState.CLOSED
        return self.state

    def allow(self, now: Optional[float] = None) -> bool:
        """Whether a call/probe is allowed right now."""
        now = now if now is not None else time.time()
        if self.state == BreakerState.OPEN and (now - self.opened_at) >= self.cooldown_s:
            self.state = BreakerState.HALF_OPEN
        return self.state in (BreakerState.CLOSED, BreakerState.HALF_OPEN)


@dataclass
class RemediationPlaybook:
    """symptom -> ordered cure steps. Steps are effector/action pairs."""
    symptom: str
    steps: List[tuple]                      # [(effector, action), ...]
    max_attempts: int = 3
    base_backoff_s: float = 0.5
    attempts: int = 0

    def next_backoff(self) -> float:
        # exponential backoff with jitter
        delay = self.base_backoff_s * (2 ** self.attempts)
        return round(delay + random.uniform(0, self.base_backoff_s), 3)


class HealingOrchestrator:
    """Reconciliation control loop + breakers + playbooks."""

    DEFAULT_PLAYBOOKS = {
        # symptom (component state / signal) -> cure steps
        "control_center:dead":   [("healing", "restart_service"), ("failover", "promote_standby")],
        "sentry_agent:dead":     [("healing", "restart_service")],
        "secure_channel:degraded": [("healing", "rekey_channel")],
        "queue:degraded":        [("healing", "drain_queue")],
        "probe_and_restart":     [("healing", "restart_service")],
    }

    def __init__(self, ns: NervousSystem, health: HealthMonitor,
                 desired_state: Optional[Dict[str, str]] = None):
        self.ns = ns
        self.health = health
        # desired state: component -> the state we want it to be in
        self.desired_state = desired_state or {}
        self.breakers: Dict[str, CircuitBreaker] = {}
        self.playbooks: Dict[str, RemediationPlaybook] = {
            k: RemediationPlaybook(k, v) for k, v in self.DEFAULT_PLAYBOOKS.items()
        }
        self.actions: List[dict] = []
        self.escalations: List[dict] = []
        # heal reflexes coming from the reflex arc (e.g. agent_silence)
        self.ns.subscribe(SignalKind.EFFERENT, self._on_command)

    def breaker(self, name: str) -> CircuitBreaker:
        if name not in self.breakers:
            self.breakers[name] = CircuitBreaker(name)
        return self.breakers[name]

    def _on_command(self, cmd: EfferentCommand):
        # The orchestrator only acts on 'healing' effector commands.
        if cmd.effector != "healing":
            return None
        return self._run_playbook(cmd.action, cmd.entity)

    def reconcile(self) -> List[dict]:
        """One control-loop tick: drive every component toward desired state."""
        self.health.sweep()
        emitted: List[dict] = []
        for name, comp in self.health.components.items():
            desired = self.desired_state.get(name, HealthState.HEALTHY.value)
            if comp.state.value == desired:
                self.breaker(name).record_success()
                continue
            # unhealthy: pick a playbook keyed by "component:state" or state alone
            key = f"{name}:{comp.state.value}"
            pb_key = key if key in self.playbooks else None
            if pb_key is None:
                # generic: any DEAD/UNHEALTHY component gets a restart attempt
                if comp.state in (HealthState.DEAD, HealthState.UNHEALTHY):
                    pb_key = f"{name}:dead" if f"{name}:dead" in self.playbooks else None
            br = self.breaker(name)
            if not br.allow():
                continue  # breaker OPEN — fail fast, wait for cooldown
            if pb_key:
                emitted += self._run_playbook(pb_key, name)
            else:
                # no known cure -> escalate to a human (matches the 90/10 ethos)
                self._escalate(name, comp.state.value, "no remediation playbook")
        return emitted

    def _run_playbook(self, key: str, entity: str) -> List[dict]:
        pb = self.playbooks.get(key)
        if pb is None:
            self._escalate(entity, key, "unknown symptom")
            return []
        if pb.attempts >= pb.max_attempts:
            self._escalate(entity, key, f"exceeded {pb.max_attempts} healing attempts")
            self.breaker(entity).record_failure()
            return []
        pb.attempts += 1
        out = []
        for effector, action in pb.steps:
            rec = {"ts": _now(), "symptom": key, "entity": entity,
                   "effector": effector, "action": action,
                   "attempt": pb.attempts, "backoff_s": pb.next_backoff(),
                   "mode": "dry-run"}
            self.actions.append(rec)
            out.append(rec)
            # emit the corrective command back onto the bus (unless it would recurse)
            if not (effector == "healing" and action == "restart_service" and key.endswith("restart")):
                self.ns.command(EfferentCommand(effector=effector, action=action,
                                                entity=entity, args={"healing": True}))
        return out

    def _escalate(self, entity: str, symptom: str, why: str) -> None:
        rec = {"ts": _now(), "entity": entity, "symptom": symptom,
               "escalated_to": "human_analyst", "why": why}
        self.escalations.append(rec)

    def mark_recovered(self, name: str) -> None:
        """Called when a component reports healthy again — resets its playbook."""
        for key, pb in self.playbooks.items():
            if key.startswith(f"{name}:"):
                pb.attempts = 0
        self.breaker(name).record_success()

    def report(self) -> dict:
        return {"actions": self.actions[-20:], "escalations": self.escalations[-20:],
                "breakers": {n: b.state.value for n, b in self.breakers.items()}}


if __name__ == "__main__":  # pragma: no cover
    ns = NervousSystem()
    hm = HealthMonitor()
    hm.register("control_center", interval=1.0)
    hm.heartbeat("control_center", cpu_percent=10)
    orch = HealingOrchestrator(ns, hm)
    # let it go dark → reconcile should attempt a heal, then eventually escalate
    hm.components["control_center"].last_beat -= 10  # force DEAD
    for _ in range(5):
        orch.reconcile()
    print("healing actions:", len(orch.actions))
    print("escalations:", len(orch.escalations))
    print("breaker:", orch.breaker("control_center").state.value)
