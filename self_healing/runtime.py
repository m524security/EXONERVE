#!/usr/bin/env python3
"""
Exonerve :: Self-Healing Runtime (wires the whole loop together)
====================================================================
Assembles the nervous system: Sensors -> NervousSystem bus -> ReflexArc (fast)
-> CNS/HealingOrchestrator (deliberate) -> Effectors, with HealthMonitor running
homeostasis in the background.

This is the single object an operator (or demo.py) instantiates to get the full
detect -> reflex -> contain -> heal -> escalate loop, all dry-run safe.
"""
from __future__ import annotations

from typing import Callable, Dict, List, Optional

from .healing_orchestrator import HealingOrchestrator
from .health_monitor import HealthMonitor
from .nervous_system import (AfferentSignal, EfferentCommand, NervousSystem,
                             Severity, SignalKind)
from .reflex_arc import ReflexArc


class SelfHealingRuntime:
    def __init__(self, effectors: Optional[Dict[str, Callable]] = None):
        self.ns = NervousSystem()
        self.health = HealthMonitor()
        self.reflex = ReflexArc(self.ns)
        self.healer = HealingOrchestrator(self.ns, self.health)
        # effector registry: effector name -> callable(EfferentCommand) (dry-run stubs)
        self.effectors: Dict[str, Callable] = effectors or {}
        self.executed: List[dict] = []
        self.ns.subscribe(SignalKind.EFFERENT, self._dispatch_effector)

    def _dispatch_effector(self, cmd: EfferentCommand):
        fn = self.effectors.get(cmd.effector)
        rec = {"effector": cmd.effector, "action": cmd.action, "entity": cmd.entity,
               "handled": fn is not None}
        if fn:
            try:
                fn(cmd)
            except Exception as exc:
                rec["error"] = str(exc)
        self.executed.append(rec)
        return rec

    def sense(self, source: str, event_type: str, severity: str, entity: str,
              techniques: Optional[List[str]] = None, **details):
        sig = AfferentSignal(source=source, event_type=event_type,
                             severity=Severity(severity), entity=entity,
                             techniques=techniques or [], details=details)
        return self.ns.sense(sig)

    def heartbeat(self, component: str, **vitals):
        return self.health.heartbeat(component, **vitals)

    def tick(self):
        """One homeostatic control-loop tick."""
        return self.healer.reconcile()

    def report(self) -> dict:
        return {"bus": self.ns.stats(),
                "health": self.health.snapshot(),
                "reflexes_fired": len(self.reflex.fired),
                "efferent_executed": len(self.executed),
                "healing": self.healer.report()}


if __name__ == "__main__":  # pragma: no cover
    isolated, healed = [], []
    rt = SelfHealingRuntime(effectors={
        "containment": lambda c: isolated.append(c.entity),
        "healing": lambda c: healed.append(c.entity),
        "failover": lambda c: None,
    })
    # register components + heartbeat
    for comp in ("control_center", "sentry_agent", "secure_channel"):
        rt.health.register(comp, interval=1.0)
        rt.heartbeat(comp, cpu_percent=15, mem_percent=30)

    # 1) a critical sensor signal -> reflex -> instant containment
    rt.sense("sentry_agent", "crypto_spike", "critical", "vm-web-01", techniques=["T1486"])
    # 2) a sensor goes dark -> health sweep -> heal attempt
    rt.health.components["sentry_agent"].last_beat -= 10
    rt.tick()

    print("isolated:", isolated)
    print("healed:", healed)
    import json
    print(json.dumps(rt.report()["bus"], indent=2))
