#!/usr/bin/env python3
"""
Exonerve :: Nervous System (typed signal bus)
=================================================
The central communication fabric between the codes. Detectors publish
*afferent* signals (something was sensed); the reflex arc and CNS publish
*reflex* and *efferent* signals (what to do). Every module talks through one
typed, auditable bus instead of ad-hoc function calls — that is what makes the
whole system stable, testable, and observable.
"""
from __future__ import annotations

import threading
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Deque, Dict, List


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class SignalKind(str, Enum):
    AFFERENT = "afferent"   # sensed input (detection/telemetry)
    REFLEX = "reflex"       # fast local response decided at the spinal level
    EFFERENT = "efferent"   # deliberate command from the CNS to an effector
    HEALTH = "health"       # homeostasis / vitals
    HEAL = "heal"           # recovery/repair action


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


@dataclass
class AfferentSignal:
    """Something was sensed by a receptor (a detector)."""
    source: str
    event_type: str
    severity: Severity
    entity: str = "unknown"          # host/ip/user/path the signal concerns
    details: dict = field(default_factory=dict)
    techniques: List[str] = field(default_factory=list)  # ATT&CK ids
    ts: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {"kind": "afferent", "source": self.source, "event_type": self.event_type,
                "severity": self.severity.value, "entity": self.entity,
                "techniques": self.techniques, "details": self.details, "ts": self.ts}


@dataclass
class ReflexSignal:
    """A fast local decision (spinal reflex) — fired before the CNS deliberates."""
    trigger: str
    action: str
    entity: str
    reason: str
    ts: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {"kind": "reflex", "trigger": self.trigger, "action": self.action,
                "entity": self.entity, "reason": self.reason, "ts": self.ts}


@dataclass
class EfferentCommand:
    """A deliberate command from the CNS to an effector (containment/failover/heal)."""
    effector: str            # e.g. "containment", "failover", "firewall", "healing"
    action: str              # e.g. "isolate_host", "promote_standby", "restart"
    entity: str
    args: dict = field(default_factory=dict)
    ts: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return {"kind": "efferent", "effector": self.effector, "action": self.action,
                "entity": self.entity, "args": self.args, "ts": self.ts}


class NervousSystem:
    """In-process typed publish/subscribe bus with an audit trail.

    Subscribers register by SignalKind. Publishing is synchronous and
    thread-safe. A bounded audit deque keeps the most recent signals for the
    dashboard / forensics without unbounded growth.
    """

    def __init__(self, audit_size: int = 1000):
        self._subs: Dict[SignalKind, List[Callable]] = defaultdict(list)
        self._audit: Deque[dict] = deque(maxlen=audit_size)
        self._lock = threading.RLock()
        self.counters: Dict[str, int] = defaultdict(int)

    def subscribe(self, kind: SignalKind, handler: Callable) -> None:
        with self._lock:
            self._subs[kind].append(handler)

    def _publish(self, kind: SignalKind, signal) -> List:
        with self._lock:
            self._audit.append(signal.to_dict())
            self.counters[kind.value] += 1
            handlers = list(self._subs.get(kind, []))
        results = []
        for h in handlers:
            try:
                results.append(h(signal))
            except Exception as exc:  # a faulty subscriber must not kill the bus
                self._audit.append({"kind": "error", "handler": getattr(h, "__name__", str(h)),
                                    "error": f"{exc.__class__.__name__}: {exc}", "ts": _now()})
        return results

    # convenience publishers
    def sense(self, sig: AfferentSignal) -> List:
        return self._publish(SignalKind.AFFERENT, sig)

    def reflex(self, sig: ReflexSignal) -> List:
        return self._publish(SignalKind.REFLEX, sig)

    def command(self, cmd: EfferentCommand) -> List:
        return self._publish(SignalKind.EFFERENT, cmd)

    def audit_log(self, n: int = 50) -> List[dict]:
        with self._lock:
            return list(self._audit)[-n:]

    def stats(self) -> dict:
        with self._lock:
            return dict(self.counters)


if __name__ == "__main__":
    ns = NervousSystem()
    seen = []
    ns.subscribe(SignalKind.AFFERENT, lambda s: seen.append(s.event_type))
    ns.sense(AfferentSignal("ids", "port_scan", Severity.MEDIUM, entity="10.0.0.9",
                            techniques=["T1046"]))
    print("handled:", seen, "| stats:", ns.stats())
