#!/usr/bin/env python3
"""
Exonerve :: Blue Team Tool — Firewall Policy Engine
=======================================================
A configuration-driven, stateful firewall *policy* layer. It evaluates a packet/
flow descriptor against an ordered rule set (first-match-wins, default-deny) and
returns ALLOW / DENY plus the matching rule — then compiles enforcement down to
the real OS backends already shipped in host_control_plane/containment.py
(iptables / nftables / netsh / pf).

The point: FW behaviour is *configuration* for the customer's environment, but
the decision logic, ordering, and enforcement wiring are Exonerve's own — so the
IPS/WAF/reflex-arc can all drive one consistent enforcement point.

Rule model (data-driven, YAML/JSON friendly):
    {action: allow|deny, dir: in|out, proto: tcp|udp|any,
     src: CIDR|any, dst: CIDR|any, port: int|range|any, note: str}

Everything is dry-run for enforcement by default (via containment backends).
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from dataclasses import dataclass
from typing import List, Optional


def _ip_in(cidr: str, ip: str) -> bool:
    if cidr in ("any", "*", "0.0.0.0/0"):
        return True
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False


def _port_match(spec, port) -> bool:
    if spec in ("any", "*", None):
        return True
    if port is None:
        return False
    if isinstance(spec, int):
        return port == spec
    if isinstance(spec, str) and "-" in spec:
        lo, hi = spec.split("-", 1)
        return int(lo) <= port <= int(hi)
    try:
        return port == int(spec)
    except (TypeError, ValueError):
        return False


@dataclass
class FwRule:
    action: str            # allow | deny
    dir: str = "in"        # in | out
    proto: str = "any"
    src: str = "any"
    dst: str = "any"
    port: object = "any"
    note: str = ""

    def matches(self, flow: dict) -> bool:
        if self.dir != flow.get("dir", "in"):
            return False
        if self.proto != "any" and self.proto != flow.get("proto", "tcp"):
            return False
        if not _ip_in(self.src, flow.get("src_ip", "0.0.0.0")):
            return False
        if not _ip_in(self.dst, flow.get("dst_ip", "0.0.0.0")):
            return False
        if not _port_match(self.port, flow.get("dst_port")):
            return False
        return True


class FirewallPolicy:
    """Ordered, default-deny policy. first-match-wins."""

    def __init__(self, rules: Optional[List[FwRule]] = None,
                 default_action: str = "deny", containment=None):
        self.rules = rules or []
        self.default_action = default_action
        # optional enforcement backend (host containment). Lazy dry-run default.
        if containment is None:
            try:
                import os, sys as _sys
                _sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..",
                                                 "host_control_plane"))
                from containment import build_backend
                containment = build_backend(dry_run=True)
            except Exception:
                containment = None
        self.containment = containment

    def add(self, rule: FwRule):
        self.rules.append(rule)

    def evaluate(self, flow: dict) -> dict:
        for i, rule in enumerate(self.rules):
            if rule.matches(flow):
                return {"action": rule.action, "rule_index": i, "note": rule.note,
                        "matched": True, "flow": flow}
        return {"action": self.default_action, "rule_index": -1,
                "note": "default policy", "matched": False, "flow": flow}

    def enforce_block(self, mgmt_allow: Optional[str] = None) -> dict:
        """Compile a hard block down to the OS containment backend (dry-run default)."""
        if self.containment is None:
            return {"enforced": False, "reason": "no containment backend"}
        actions = self.containment.isolate_host(mgmt_allow=mgmt_allow)
        return {"enforced": True, "backend": self.containment.name,
                "dry_run": self.containment.dry_run, "actions": actions}

    @classmethod
    def from_config(cls, cfg: List[dict], default_action: str = "deny") -> "FirewallPolicy":
        return cls([FwRule(**r) for r in cfg], default_action=default_action)


def _selftest() -> int:
    # A small default-deny policy: allow web in, allow DNS out, deny known-bad.
    policy = FirewallPolicy.from_config([
        {"action": "deny", "dir": "out", "dst": "185.220.1.9/32", "note": "known C2"},
        {"action": "allow", "dir": "in", "proto": "tcp", "port": 443, "note": "https"},
        {"action": "allow", "dir": "out", "proto": "udp", "port": 53, "note": "dns"},
    ], default_action="deny")

    cases = [
        ({"dir": "in", "proto": "tcp", "src_ip": "1.2.3.4", "dst_ip": "10.0.0.9", "dst_port": 443}, "allow"),
        ({"dir": "out", "proto": "tcp", "src_ip": "10.0.0.9", "dst_ip": "185.220.1.9", "dst_port": 443}, "deny"),
        ({"dir": "out", "proto": "udp", "src_ip": "10.0.0.9", "dst_ip": "8.8.8.8", "dst_port": 53}, "allow"),
        ({"dir": "in", "proto": "tcp", "src_ip": "1.2.3.4", "dst_ip": "10.0.0.9", "dst_port": 22}, "deny"),  # default
    ]
    ok = 0
    for flow, expect in cases:
        r = policy.evaluate(flow)
        status = "PASS" if r["action"] == expect else "FAIL"
        if r["action"] == expect:
            ok += 1
        print(f"  [{status}] {flow['dir']:3} {flow.get('dst_ip'):14}:{flow.get('dst_port'):<5} "
              f"-> {r['action']:5} ({r['note']})")
    # enforcement compiles to a dry-run backend
    enf = policy.enforce_block(mgmt_allow="10.0.0.0/24")
    en_ok = enf.get("enforced") and enf.get("dry_run") is True
    print(f"  [{'PASS' if en_ok else 'FAIL'}] enforce_block -> backend={enf.get('backend')} dry_run={enf.get('dry_run')}")
    if en_ok:
        ok += 1
    total = len(cases) + 1
    print(f"\nFirewall self-test: {ok}/{total} passed")
    return 0 if ok == total else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Exonerve firewall policy engine")
    ap.add_argument("--test", action="store_true")
    ap.add_argument("--eval", help="JSON flow to evaluate")
    args = ap.parse_args()
    if args.eval:
        pol = FirewallPolicy.from_config([{"action": "allow", "dir": "in", "port": 443}])
        print(json.dumps(pol.evaluate(json.loads(args.eval)), indent=2))
    else:
        sys.exit(_selftest())
