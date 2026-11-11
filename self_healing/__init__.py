"""
Exonerve :: Self-Healing Subsystem (biologically-inspired)
==============================================================
Models the platform's detect→respond→recover loop on the human nervous system,
because that system already solves the problem we care about: sense damage,
react instantly at the reflex level, escalate to the brain for judgement, and
restore the body toward a healthy baseline (homeostasis) — continuously.

Mapping (biology -> Exonerve):
    sensory receptors   -> Sensors  (sentry_agent, IDS/WAF/blue-team tools)
    afferent nerves     -> SecureChannel telemetry inbound
    spinal reflex arc   -> ReflexArc      (instant local response, no CNS wait)
    brain / CNS         -> NervousSystem bus + control_center correlation
    efferent nerves     -> EfferentCommand dispatch
    effectors (muscles) -> containment / firewall / failover / heal actions
    homeostasis         -> HealthMonitor  (keep components in a healthy range)
    healing / repair    -> HealingOrchestrator (restart, reconcile, restore)
    immune memory       -> persisted IOCs / baselines

Everything here is stdlib-only and side-effect-free by default (dry-run),
so it is safe to import, test, and demo anywhere.
"""
from .nervous_system import (NervousSystem, AfferentSignal, ReflexSignal,
                             EfferentCommand, SignalKind, Severity)
from .health_monitor import HealthMonitor, ComponentHealth, HealthState
from .reflex_arc import ReflexArc
from .healing_orchestrator import HealingOrchestrator, CircuitBreaker, RemediationPlaybook
from .runtime import SelfHealingRuntime

__all__ = [
    "NervousSystem", "AfferentSignal", "ReflexSignal", "EfferentCommand",
    "SignalKind", "Severity", "HealthMonitor", "ComponentHealth", "HealthState",
    "ReflexArc", "HealingOrchestrator", "CircuitBreaker", "RemediationPlaybook",
    "SelfHealingRuntime",
]
