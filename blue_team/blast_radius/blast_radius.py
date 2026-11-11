#!/usr/bin/env python3
"""
Exonerve :: Blue Team Tool — Blast-Radius / Reachability Mapper (self-built)
===============================================================================
Given a compromised asset, computes what an adversary can reach from it — the
*blast radius* — over a declared network/trust graph, using a deterministic BFS
(no ML). It returns:
  * the set of reachable assets and the shortest path to each,
  * a blast-radius score (how much of the estate, weighted by asset value, is
    exposed from the compromise),
  * the most critical asset reachable (feeds `asset_criticality` into the
    deterministic decision engine — a compromise that can reach a crown jewel
    should bias the response toward FAILOVER/CONTAIN).

This is a small, auditable graph tool — not a clone of any scanner. It reasons
over a graph YOU declare (segments, trust edges, allowed ports), so it models
*your* intended architecture and shows where segmentation is too flat.
"""
from __future__ import annotations

import sys
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional


# asset value weights (for the blast-radius score)
_VALUE = {"low": 1, "normal": 2, "high": 5, "crown_jewel": 10}


@dataclass
class Asset:
    id: str
    value: str = "normal"          # low|normal|high|crown_jewel
    segment: str = "default"

    @property
    def weight(self) -> int:
        return _VALUE.get(self.value, 2)


@dataclass
class NetworkModel:
    """Declared reachability graph. edges[a] = set of assets a can reach directly."""
    assets: Dict[str, Asset] = field(default_factory=dict)
    edges: Dict[str, List[str]] = field(default_factory=dict)

    def add_asset(self, aid: str, value: str = "normal", segment: str = "default"):
        self.assets[aid] = Asset(aid, value, segment)
        self.edges.setdefault(aid, [])

    def add_edge(self, a: str, b: str, bidirectional: bool = True):
        self.edges.setdefault(a, [])
        if b not in self.edges[a]:
            self.edges[a].append(b)
        if bidirectional:
            self.edges.setdefault(b, [])
            if a not in self.edges[b]:
                self.edges[b].append(a)


@dataclass
class BlastRadius:
    origin: str
    reachable: Dict[str, int]              # asset -> hop distance
    paths: Dict[str, List[str]]            # asset -> shortest path
    score: float                            # 0..1 fraction of weighted estate exposed
    most_critical: Optional[str]
    most_critical_value: str

    def to_dict(self) -> dict:
        return {"origin": self.origin, "reachable": self.reachable, "paths": self.paths,
                "score": round(self.score, 3), "most_critical": self.most_critical,
                "most_critical_value": self.most_critical_value}

    def narrative(self) -> str:
        n = len(self.reachable)
        crit = f" — reaches a {self.most_critical_value} ({self.most_critical})" \
               if self.most_critical else ""
        return (f"From {self.origin}: {n} asset(s) reachable, "
                f"blast radius {self.score:.0%} of the estate{crit}.")


class BlastRadiusMapper:
    def compute(self, model: NetworkModel, origin: str) -> BlastRadius:
        if origin not in model.edges:
            return BlastRadius(origin, {}, {}, 0.0, None, "none")
        # BFS shortest paths
        dist = {origin: 0}
        prev: Dict[str, str] = {}
        q = deque([origin])
        while q:
            cur = q.popleft()
            for nxt in model.edges.get(cur, []):
                if nxt not in dist:
                    dist[nxt] = dist[cur] + 1
                    prev[nxt] = cur
                    q.append(nxt)
        reachable = {a: d for a, d in dist.items() if a != origin}
        paths = {a: self._path(prev, origin, a) for a in reachable}

        # weighted blast-radius score
        total_weight = sum(model.assets.get(a, Asset(a)).weight for a in model.assets) or 1
        exposed_weight = sum(model.assets.get(a, Asset(a)).weight for a in reachable)
        score = exposed_weight / total_weight

        # most critical reachable asset
        most_critical, mcv = None, "none"
        best = -1
        for a in reachable:
            w = model.assets.get(a, Asset(a)).weight
            if w > best:
                best, most_critical, mcv = w, a, model.assets.get(a, Asset(a)).value
        return BlastRadius(origin, reachable, paths, score, most_critical, mcv)

    @staticmethod
    def _path(prev: Dict[str, str], origin: str, target: str) -> List[str]:
        out = [target]
        while out[-1] != origin and out[-1] in prev:
            out.append(prev[out[-1]])
        out.reverse()
        return out

    @staticmethod
    def to_decision_criticality(br: BlastRadius) -> str:
        """Map a blast radius to the asset_criticality the decision engine consumes."""
        if br.most_critical_value == "crown_jewel" or br.score >= 0.5:
            return "crown_jewel"
        if br.most_critical_value == "high" or br.score >= 0.25:
            return "high"
        return "normal"


def _demo_model() -> NetworkModel:
    m = NetworkModel()
    m.add_asset("web-dmz", "normal", "dmz")
    m.add_asset("app-01", "normal", "app")
    m.add_asset("app-02", "normal", "app")
    m.add_asset("db-core", "crown_jewel", "data")
    m.add_asset("backup", "high", "data")
    m.add_asset("workstation", "low", "office")
    m.add_edge("web-dmz", "app-01")
    m.add_edge("app-01", "app-02")
    m.add_edge("app-02", "db-core")     # flat: app tier can reach the crown jewel
    m.add_edge("db-core", "backup")
    m.add_edge("workstation", "web-dmz")
    return m


def _selftest() -> int:
    m = _demo_model()
    mapper = BlastRadiusMapper()
    br = mapper.compute(m, "web-dmz")
    print("  " + br.narrative())
    ok, total = 0, 4
    if "db-core" in br.reachable:
        ok += 1; print("  [PASS] crown jewel reachable from DMZ (segmentation gap found)")
    if br.most_critical == "db-core":
        ok += 1; print("  [PASS] identifies db-core as most-critical reachable")
    if mapper.to_decision_criticality(br) == "crown_jewel":
        ok += 1; print("  [PASS] maps to 'crown_jewel' criticality for the decision engine")
    # an isolated asset has zero blast radius
    m.add_asset("island", "normal", "isolated")
    br2 = mapper.compute(m, "island")
    if br2.score == 0.0 and not br2.reachable:
        ok += 1; print("  [PASS] isolated asset has zero blast radius")
    print(f"\nBlast-radius mapper self-test: {ok}/{total} passed")
    return 0 if ok == total else 1


if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser(description="Exonerve blast-radius mapper")
    ap.add_argument("--test", action="store_true")
    ap.add_argument("--origin", help="compute blast radius from this asset (demo model)")
    args = ap.parse_args()
    if args.origin:
        br = BlastRadiusMapper().compute(_demo_model(), args.origin)
        print(br.narrative()); print(json.dumps(br.to_dict(), indent=2))
    else:
        sys.exit(_selftest())
