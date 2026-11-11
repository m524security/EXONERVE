#!/usr/bin/env python3
"""
Exonerve :: Blue Team Tool — Kill-Chain Reconstructor (self-built)
=====================================================================
Takes a stream of detections (each mapped to ATT&CK techniques) and reconstructs
the adversary's kill chain: it orders the observed techniques by ATT&CK tactic
progression (Recon → Initial Access → Execution → … → Impact), scores how far
along the chain the adversary has advanced, and flags the *stage* so responders
know whether they're watching recon or active impact.

This is not a clone of anything — it's a small, deterministic correlation tool
that turns scattered alerts into a single narrative + a "chain completeness"
metric the decision engine can use (deeper chain ⇒ more decisive response).

No ML, no external calls. Pure ordering + scoring over the ATT&CK tactic model.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from common.mitre_attack import TECHNIQUES, TACTICS  # noqa: E402

# canonical ATT&CK tactic progression (kill-chain order)
_TACTIC_ORDER = [
    "TA0043",  # Reconnaissance
    "TA0001",  # Initial Access
    "TA0002",  # Execution
    "TA0003",  # Persistence
    "TA0004",  # Privilege Escalation
    "TA0005",  # Defense Evasion
    "TA0006",  # Credential Access
    "TA0007",  # Discovery
    "TA0008",  # Lateral Movement
    "TA0009",  # Collection
    "TA0011",  # Command and Control
    "TA0010",  # Exfiltration
    "TA0040",  # Impact
]
_ORDER_INDEX = {t: i for i, t in enumerate(_TACTIC_ORDER)}


@dataclass
class ChainStep:
    tactic_id: str
    tactic_name: str
    order: int
    techniques: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"tactic": self.tactic_name, "tactic_id": self.tactic_id,
                "order": self.order, "techniques": self.techniques}


@dataclass
class KillChain:
    steps: List[ChainStep]
    completeness: float           # 0..1 how far along the chain
    furthest_stage: str
    reached_impact: bool

    def narrative(self) -> str:
        if not self.steps:
            return "No mapped techniques observed."
        parts = [f"{s.tactic_name} ({', '.join(s.techniques)})" for s in self.steps]
        line = " → ".join(parts)
        tail = "  ⚠ REACHED IMPACT" if self.reached_impact else ""
        return f"{line}   [chain {self.completeness:.0%}, furthest: {self.furthest_stage}]{tail}"

    def to_dict(self) -> dict:
        return {"steps": [s.to_dict() for s in self.steps],
                "completeness": round(self.completeness, 3),
                "furthest_stage": self.furthest_stage,
                "reached_impact": self.reached_impact}


class KillChainReconstructor:
    def reconstruct(self, technique_ids: List[str]) -> KillChain:
        """Order observed techniques into kill-chain stages."""
        by_tactic: Dict[str, List[str]] = {}
        for tid in technique_ids:
            tech = TECHNIQUES.get(tid)
            if not tech:
                continue
            for ta in tech.tactics:
                if ta in _ORDER_INDEX:
                    by_tactic.setdefault(ta, [])
                    if tid not in by_tactic[ta]:
                        by_tactic[ta].append(tid)

        steps = [ChainStep(ta, _tactic_name(ta), _ORDER_INDEX[ta], sorted(tids))
                 for ta, tids in by_tactic.items()]
        steps.sort(key=lambda s: s.order)

        if steps:
            furthest = max(steps, key=lambda s: s.order)
            completeness = (furthest.order + 1) / len(_TACTIC_ORDER)
            reached_impact = furthest.tactic_id == "TA0040"
            furthest_stage = furthest.tactic_name
        else:
            completeness, reached_impact, furthest_stage = 0.0, False, "none"
        return KillChain(steps, completeness, furthest_stage, reached_impact)


def _tactic_name(ta: str) -> str:
    v = TACTICS.get(ta, ta)
    return v if isinstance(v, str) else ta


def _selftest() -> int:
    kc = KillChainReconstructor()
    # a realistic ransomware chain: recon → exec → cred access → C2 → exfil → impact
    chain = kc.reconstruct(["T1595", "T1059.001", "T1003.001", "T1071",
                            "T1567.002", "T1486"])
    print("  " + chain.narrative())
    ok = 0
    total = 4
    if chain.reached_impact:
        ok += 1; print("  [PASS] detected chain reached Impact")
    if chain.completeness == 1.0:
        ok += 1; print("  [PASS] completeness 100% (Impact is last stage)")
    if [s.tactic_id for s in chain.steps] == sorted(
            [s.tactic_id for s in chain.steps], key=lambda t: _ORDER_INDEX[t]):
        ok += 1; print("  [PASS] steps correctly ordered by tactic progression")
    early = kc.reconstruct(["T1595"])  # recon only — genuinely early
    if not early.reached_impact and early.completeness < 0.6:
        ok += 1; print(f"  [PASS] early-stage chain flagged (completeness {early.completeness:.0%})")
    print(f"\nKill-chain reconstructor self-test: {ok}/{total} passed")
    return 0 if ok == total else 1


if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser(description="Exonerve kill-chain reconstructor")
    ap.add_argument("--test", action="store_true")
    ap.add_argument("--techniques", help="comma-separated ATT&CK ids to reconstruct")
    args = ap.parse_args()
    if args.techniques:
        kc = KillChainReconstructor().reconstruct(
            [t.strip() for t in args.techniques.split(",")])
        print(kc.narrative())
        print(json.dumps(kc.to_dict(), indent=2))
    else:
        sys.exit(_selftest())
