#!/usr/bin/env python3
"""
Exonerve :: Reflex Arc (spinal-level fast path)
===================================================
In biology a reflex (e.g. pulling your hand off a hot stove) is handled by the
spinal cord BEFORE the brain is even aware — because waiting for the brain would
be too slow. Exonerve mirrors this: a small set of unambiguous, high-confidence
signals trigger an immediate protective action locally, without waiting for the
full correlation/scoring pass in the CNS.

This is what gives Exonerve its millisecond containment on the signals that
leave no room for doubt (mass encryption, LSASS dumping, ESXi encryption).
"""
from __future__ import annotations

from typing import Dict, List, Optional

from .nervous_system import (AfferentSignal, EfferentCommand, NervousSystem,
                             ReflexSignal, Severity, SignalKind)


class ReflexArc:
    """Maps high-confidence afferent signals to instant efferent commands.

    Reflexes are intentionally few and unambiguous — a reflex must never fire on
    a low-confidence signal (that is the CNS's job). Each reflex names the
    effector + action so the audit trail explains exactly why it fired.
    """

    # event_type -> (effector, action, human reason)
    DEFAULT_REFLEXES: Dict[str, tuple] = {
        "crypto_spike":    ("containment", "isolate_host", "mass file encryption in progress"),
        "cred_dump":       ("containment", "isolate_host", "LSASS credential dumping"),
        "ransomware_esxi": ("containment", "isolate_host", "ESXi datastore encryption"),
        "agent_silence":   ("healing", "probe_and_restart", "sensor went dark — possible tamper"),
    }

    def __init__(self, ns: NervousSystem, reflexes: Optional[Dict[str, tuple]] = None):
        self.ns = ns
        self.reflexes = dict(self.DEFAULT_REFLEXES)
        if reflexes:
            self.reflexes.update(reflexes)
        # subscribe to sensed input; fire reflexes synchronously
        self.ns.subscribe(SignalKind.AFFERENT, self._on_afferent)
        self.fired: List[dict] = []

    def _on_afferent(self, sig: AfferentSignal):
        # Only the most severe, unambiguous signals get a reflex.
        rule = self.reflexes.get(sig.event_type)
        if not rule:
            return None
        if sig.severity.rank < Severity.HIGH.rank:
            return None
        effector, action, reason = rule
        rs = ReflexSignal(trigger=sig.event_type, action=action,
                          entity=sig.entity, reason=reason)
        self.ns.reflex(rs)
        cmd = EfferentCommand(effector=effector, action=action,
                              entity=sig.entity,
                              args={"reflex": True, "reason": reason,
                                    "techniques": sig.techniques})
        self.ns.command(cmd)
        self.fired.append(rs.to_dict())
        return cmd


if __name__ == "__main__":  # pragma: no cover  (run via: python -m self_healing.reflex_arc)
    ns = NervousSystem()
    commands = []
    ns.subscribe(SignalKind.EFFERENT, lambda c: commands.append((c.effector, c.action)))
    arc = ReflexArc(ns)
    # high-confidence -> reflex fires
    ns.sense(AfferentSignal("sentry", "crypto_spike", Severity.CRITICAL, entity="vm-web-01",
                            techniques=["T1486"]))
    # low-confidence -> no reflex
    ns.sense(AfferentSignal("ids", "network", Severity.LOW, entity="vm-web-01"))
    print("efferent commands:", commands)
    print("reflexes fired:", [f["trigger"] for f in arc.fired])
