#!/usr/bin/env python3
"""
Exonerve :: Deterministic Decision Engine
=============================================
Chooses the incident response (MONITOR / ALERT / CONTAIN / FAILOVER / HEAL /
ESCALATE) from facts about an event, using a weighted forward-chaining rule set
plus hard safety gates — no machine learning anywhere.

How it decides (three transparent layers):
  1. HARD GATES   — non-negotiable safety rules evaluated first. e.g. "child of a
                    reflex-worthy signal ⇒ CONTAIN, always." These cannot be
                    outvoted by scores.
  2. WEIGHTED RULES — every matching rule contributes a signed weight toward each
                    candidate action; the highest total wins. This is a simple,
                    inspectable scoring model (think: a scorecard, not a neural net).
  3. CONFIDENCE + ESCALATION — if the winning margin is thin, or the situation is
                    ambiguous/novel, it ESCALATES TO A HUMAN rather than guessing.
                    (The 90/10 philosophy, encoded.)

Everything returns a Decision object carrying the chosen action, a numeric
confidence, and the full list of fired rules with their contributions — so an
analyst can read exactly why the system decided what it did.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Dict, List, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Verdict(str, Enum):
    MONITOR = "monitor"      # nothing to do; keep observing
    ALERT = "alert"          # raise to the SOC queue
    CONTAIN = "contain"      # isolate host at the network layer
    FAILOVER = "failover"    # promote standby, keep the workload alive
    HEAL = "heal"            # run remediation / restore
    ESCALATE = "escalate"    # hand to a human analyst


class Action(str, Enum):
    # concrete effector actions a Verdict may imply
    NONE = "none"
    RAISE_ALERT = "raise_alert"
    ISOLATE_HOST = "isolate_host"
    PROMOTE_STANDBY = "promote_standby"
    RESTORE_SNAPSHOT = "restore_snapshot"
    NOTIFY_ANALYST = "notify_analyst"


@dataclass
class Fact:
    """The normalized inputs the engine reasons over."""
    event_type: str = ""
    severity: str = "info"          # info|low|medium|high|critical
    score: int = 0                  # server-side cumulative score
    techniques: List[str] = field(default_factory=list)  # ATT&CK ids
    asset_criticality: str = "normal"   # low|normal|high|crown_jewel
    has_standby: bool = False
    reversible: bool = True         # is the action safe to auto-take?
    business_hours: bool = True
    repeat_offender: bool = False   # same entity seen before
    extra: dict = field(default_factory=dict)

    _SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    @property
    def sev_rank(self) -> int:
        return self._SEV.get(self.severity, 0)


@dataclass
class Condition:
    """A named predicate over a Fact. Pure, deterministic, testable."""
    name: str
    test: Callable[[Fact], bool]

    def holds(self, f: Fact) -> bool:
        try:
            return bool(self.test(f))
        except Exception:
            return False


@dataclass
class Rule:
    """If all conditions hold, contribute `weight` toward `verdict`."""
    id: str
    conditions: List[Condition]
    verdict: Verdict
    weight: int
    rationale: str
    hard_gate: bool = False   # if True and it fires, it forces the verdict

    def fires(self, f: Fact) -> bool:
        return all(c.holds(f) for c in self.conditions)


@dataclass
class Decision:
    verdict: Verdict
    action: Action
    confidence: float                    # 0..1
    fired: List[dict]                    # [{rule, verdict, weight, rationale}]
    scores: Dict[str, int]               # verdict -> total weight
    escalated: bool
    ts: str = field(default_factory=_now)

    def explain(self) -> str:
        lines = [f"DECISION: {self.verdict.value.upper()} "
                 f"(action={self.action.value}, confidence={self.confidence:.2f}"
                 f"{', ESCALATED' if self.escalated else ''})",
                 "  because:"]
        for r in self.fired:
            sign = "+" if r["weight"] >= 0 else ""
            lines.append(f"    [{sign}{r['weight']:>3}] {r['verdict']:<9} {r['id']}: {r['rationale']}")
        lines.append("  totals: " + ", ".join(f"{k}={v}" for k, v in
                                               sorted(self.scores.items(), key=lambda kv: -kv[1]) if v))
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {"verdict": self.verdict.value, "action": self.action.value,
                "confidence": round(self.confidence, 3), "escalated": self.escalated,
                "fired": self.fired, "scores": self.scores, "ts": self.ts}


# verdict -> the concrete effector action it implies
_VERDICT_ACTION = {
    Verdict.MONITOR: Action.NONE,
    Verdict.ALERT: Action.RAISE_ALERT,
    Verdict.CONTAIN: Action.ISOLATE_HOST,
    Verdict.FAILOVER: Action.PROMOTE_STANDBY,
    Verdict.HEAL: Action.RESTORE_SNAPSHOT,
    Verdict.ESCALATE: Action.NOTIFY_ANALYST,
}


def _c(name, fn) -> Condition:
    return Condition(name, fn)


def default_rules() -> List[Rule]:
    """The shipped policy. Every rule is readable and independently testable."""
    high = _c("sev>=high", lambda f: f.sev_rank >= 3)
    crit = _c("sev==critical", lambda f: f.sev_rank >= 4)
    return [
        # --- HARD GATES (safety, cannot be outvoted) ---
        Rule("G1", [_c("reflex_signal", lambda f: f.event_type in
                       {"crypto_spike", "cred_dump", "ransomware_esxi"}), crit],
             Verdict.CONTAIN, 1000, "unambiguous destructive signal → isolate now",
             hard_gate=True),
        Rule("G2", [_c("irreversible_action", lambda f: not f.reversible),
                    _c("not_certain", lambda f: f.sev_rank < 4)],
             Verdict.ESCALATE, 1000, "action is irreversible and not certain → human decides",
             hard_gate=True),

        # --- WEIGHTED RULES ---
        Rule("R1", [crit], Verdict.CONTAIN, 60, "critical severity favors containment"),
        Rule("R2", [high], Verdict.ALERT, 30, "high severity warrants an alert"),
        Rule("R3", [_c("score>=100", lambda f: f.score >= 100)],
             Verdict.CONTAIN, 50, "cumulative score crossed isolation threshold"),
        Rule("R4", [_c("contain_and_standby", lambda f: f.sev_rank >= 3 and f.has_standby)],
             Verdict.FAILOVER, 45, "high severity + a warm standby → keep workload alive"),
        Rule("R5", [_c("crown_jewel", lambda f: f.asset_criticality in ("high", "crown_jewel")),
                    high],
             Verdict.FAILOVER, 25, "critical asset: prefer continuity over pure isolation"),
        Rule("R6", [_c("low_sev", lambda f: f.sev_rank <= 1)],
             Verdict.MONITOR, 40, "low severity: observe, don't act"),
        Rule("R7", [_c("medium_sev", lambda f: f.sev_rank == 2)],
             Verdict.ALERT, 35, "medium severity: alert the SOC"),
        Rule("R8", [_c("repeat", lambda f: f.repeat_offender), high],
             Verdict.CONTAIN, 20, "repeat offender escalates confidence to contain"),
        Rule("R9", [_c("post_contain", lambda f: f.event_type == "agent_silence")],
             Verdict.HEAL, 30, "sensor dark after an incident → heal/restore path"),
        Rule("R10", [_c("off_hours_crit", lambda f: (not f.business_hours) and f.sev_rank >= 3)],
             Verdict.CONTAIN, 15, "off-hours high severity: lean toward automated containment"),
        # a mild bias to ALERT so nothing is silently dropped
        Rule("R0", [_c("any", lambda f: True)], Verdict.ALERT, 5, "baseline: never silently ignore"),
    ]


class DecisionEngine:
    def __init__(self, rules: Optional[List[Rule]] = None,
                 escalate_margin: int = 15):
        self.rules = rules if rules is not None else default_rules()
        self.escalate_margin = escalate_margin

    def decide(self, fact: Fact) -> Decision:
        fired: List[dict] = []
        scores: Dict[str, int] = {v.value: 0 for v in Verdict}

        # 1) hard gates first — first firing gate wins outright
        for r in self.rules:
            if r.hard_gate and r.fires(fact):
                fired.append({"id": r.id, "verdict": r.verdict.value,
                              "weight": r.weight, "rationale": r.rationale})
                return Decision(r.verdict, _VERDICT_ACTION[r.verdict], 1.0,
                                fired, {r.verdict.value: r.weight},
                                escalated=(r.verdict == Verdict.ESCALATE))

        # 2) weighted accumulation
        for r in self.rules:
            if not r.hard_gate and r.fires(fact):
                scores[r.verdict.value] += r.weight
                fired.append({"id": r.id, "verdict": r.verdict.value,
                              "weight": r.weight, "rationale": r.rationale})

        # 3) pick winner + confidence + escalation on thin margins
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        top_v, top_s = ranked[0]
        second_s = ranked[1][1] if len(ranked) > 1 else 0
        total = sum(max(0, s) for s in scores.values()) or 1
        confidence = round(top_s / total, 3)
        margin = top_s - second_s

        escalated = False
        verdict = Verdict(top_v)
        if margin < self.escalate_margin and top_s > 0:
            # ambiguous → don't guess; escalate but record the leading candidate
            escalated = True
            verdict = Verdict.ESCALATE
            fired.append({"id": "ESC", "verdict": "escalate",
                          "weight": 0,
                          "rationale": f"margin {margin} < {self.escalate_margin} "
                                       f"(leading: {top_v}) → human decides"})

        return Decision(verdict, _VERDICT_ACTION[verdict], confidence,
                        fired, {k: v for k, v in scores.items() if v}, escalated)


if __name__ == "__main__":
    eng = DecisionEngine()
    scenarios = {
        "ransomware (critical)": Fact("crypto_spike", "critical", score=50,
                                      techniques=["T1486"], has_standby=True),
        "high sev + standby":    Fact("network", "high", score=60, has_standby=True,
                                      asset_criticality="crown_jewel"),
        "medium recon":          Fact("lolbin", "medium", score=30),
        "low noise":             Fact("heartbeat", "low", score=0),
        "irreversible+unsure":   Fact("driver_load", "medium", score=40, reversible=False),
        "ambiguous tie":         Fact("persistence", "high", score=90),
    }
    for name, f in scenarios.items():
        d = eng.decide(f)
        print(f"\n### {name}")
        print(d.explain())
