#!/usr/bin/env python3
"""
Exonerve :: Health Monitor (homeostasis)
============================================
Keeps every component inside a healthy operating range, exactly like biological
homeostasis. Each component emits a heartbeat with vitals; the monitor decides
HEALTHY / DEGRADED / UNHEALTHY / DEAD and emits HEALTH signals the healing
orchestrator acts on. This is what makes the platform *stable* under stress.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional


class HealthState(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    DEAD = "dead"


@dataclass
class ComponentHealth:
    name: str
    interval: float = 5.0            # expected heartbeat interval (s)
    last_beat: float = field(default_factory=time.time)
    misses: int = 0
    state: HealthState = HealthState.HEALTHY
    vitals: dict = field(default_factory=dict)
    consecutive_ok: int = 0

    def to_dict(self) -> dict:
        return {"name": self.name, "state": self.state.value, "misses": self.misses,
                "vitals": self.vitals,
                "age_s": round(time.time() - self.last_beat, 2)}


class HealthMonitor:
    """Watchdog + vitals evaluator. Thresholds map missed heartbeats and vital
    ranges to a health state — the biological 'set point' logic."""

    # missed-heartbeat thresholds -> state
    DEGRADED_AFTER = 1
    UNHEALTHY_AFTER = 2
    DEAD_AFTER = 4

    def __init__(self):
        self.components: Dict[str, ComponentHealth] = {}

    def register(self, name: str, interval: float = 5.0) -> ComponentHealth:
        c = ComponentHealth(name=name, interval=interval)
        self.components[name] = c
        return c

    def heartbeat(self, name: str, **vitals) -> ComponentHealth:
        c = self.components.get(name) or self.register(name)
        c.last_beat = time.time()
        c.misses = 0
        c.vitals = vitals
        c.consecutive_ok += 1
        c.state = self._evaluate_vitals(c)
        return c

    def _evaluate_vitals(self, c: ComponentHealth) -> HealthState:
        # Vital set-points (homeostasis). Out-of-range => DEGRADED even if alive.
        cpu = c.vitals.get("cpu_percent")
        mem = c.vitals.get("mem_percent")
        q = c.vitals.get("queue_depth")
        err = c.vitals.get("error_rate")
        if (cpu is not None and cpu >= 95) or (mem is not None and mem >= 95) \
           or (q is not None and q >= 1000) or (err is not None and err >= 0.5):
            return HealthState.DEGRADED
        return HealthState.HEALTHY

    def sweep(self, now: Optional[float] = None) -> Dict[str, HealthState]:
        """Age every component by missed heartbeats and update state. Returns the
        components whose state changed this sweep."""
        now = now if now is not None else time.time()
        changed: Dict[str, HealthState] = {}
        for c in self.components.values():
            prev = c.state
            elapsed = now - c.last_beat
            c.misses = int(elapsed // c.interval)
            if c.misses >= self.DEAD_AFTER:
                c.state = HealthState.DEAD
            elif c.misses >= self.UNHEALTHY_AFTER:
                c.state = HealthState.UNHEALTHY
            elif c.misses >= self.DEGRADED_AFTER:
                c.state = HealthState.DEGRADED
            else:
                c.state = self._evaluate_vitals(c)
            if c.state != prev:
                c.consecutive_ok = 0 if c.state != HealthState.HEALTHY else c.consecutive_ok
                changed[c.name] = c.state
        return changed

    def snapshot(self) -> dict:
        return {n: c.to_dict() for n, c in self.components.items()}

    def unhealthy(self):
        return [c for c in self.components.values()
                if c.state in (HealthState.UNHEALTHY, HealthState.DEAD)]


if __name__ == "__main__":
    hm = HealthMonitor()
    hm.register("control_center", interval=1.0)
    hm.heartbeat("control_center", cpu_percent=20, mem_percent=40)
    print("fresh:", hm.components["control_center"].state.value)
    # simulate 3s of silence
    changed = hm.sweep(now=time.time() + 3.2)
    print("after silence:", hm.components["control_center"].state.value, "| changed:", {k: v.value for k, v in changed.items()})
