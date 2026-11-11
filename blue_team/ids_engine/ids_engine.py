#!/usr/bin/env python3
"""
Exonerve :: Blue Team Tool — IDS/IPS Engine (network intrusion detection)
=============================================================================
A configuration-driven network IDS with an inline IPS mode.

  IDS mode  : evaluates connection/flow events and raises findings.
  IPS mode  : returns an inline verdict (ALLOW / DROP / RESET) so an enforcement
              point (the firewall / containment layer) can act on it.

Two detection strategies, both standard:
  1. SIGNATURE  — known-bad indicators (malicious IPs, C2 ports, tool fingerprints).
  2. ANOMALY    — stateful heuristics over a short window per source:
       * port scan          (many distinct dst ports in a short time)  -> T1046
       * host sweep         (many distinct dst hosts)                  -> T1046
       * C2 beacon          (regular low-jitter callback to one dst)   -> T1071/T1571
       * brute force        (many auth failures)                       -> T1110

Stdlib-only, side-effect-free. Feed it events; it holds a rolling per-source
state and returns verdicts you can wire to the firewall.
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, List

KNOWN_BAD_IPS = {"185.220.1.9", "45.155.205.233", "193.169.255.10"}  # sample TI
C2_PORTS = {4444, 1337, 8443, 6667, 9001, 31337}


@dataclass
class Finding:
    rule: str
    severity: str
    attack: List[str]
    src: str
    dst: str
    detail: str
    verdict: str = "ALLOW"

    def to_dict(self) -> dict:
        return self.__dict__


class IDSEngine:
    def __init__(self, mode: str = "ids", window_s: float = 10.0,
                 scan_ports_threshold: int = 15, sweep_hosts_threshold: int = 15,
                 bruteforce_threshold: int = 10, beacon_min_samples: int = 4):
        assert mode in ("ids", "ips")
        self.mode = mode
        self.window_s = window_s
        self.scan_ports_threshold = scan_ports_threshold
        self.sweep_hosts_threshold = sweep_hosts_threshold
        self.bruteforce_threshold = bruteforce_threshold
        self.beacon_min_samples = beacon_min_samples
        # per-source rolling state
        self._ports: Dict[str, Deque] = defaultdict(deque)
        self._hosts: Dict[str, Deque] = defaultdict(deque)
        self._auth_fail: Dict[str, Deque] = defaultdict(deque)
        self._beacon: Dict[str, Deque] = defaultdict(deque)

    def _prune(self, dq: Deque, now: float):
        while dq and now - dq[0][0] > self.window_s:
            dq.popleft()

    def _verdict(self, severity: str) -> str:
        if self.mode != "ips":
            return "ALLOW"
        return "DROP" if severity in ("high", "critical") else "ALLOW"

    def inspect(self, ev: dict) -> List[Finding]:
        """ev keys: src_ip, dst_ip, dst_port, proto, event('conn'|'auth_fail'), ts, outcome."""
        now = ev.get("ts", time.time())
        src = ev.get("src_ip", "?")
        dst = ev.get("dst_ip", "?")
        port = ev.get("dst_port")
        findings: List[Finding] = []

        # 1) signature: known-bad IP
        if src in KNOWN_BAD_IPS or dst in KNOWN_BAD_IPS:
            findings.append(Finding("SIG-BADIP", "high", ["T1071"], src, dst,
                                    "connection with known-malicious IP"))
        # 2) signature: C2 port
        if port in C2_PORTS:
            findings.append(Finding("SIG-C2PORT", "high", ["T1571"], src, dst,
                                    f"connection to known C2 port {port}"))

        # 3) anomaly: port scan
        if port is not None:
            dq = self._ports[src]; dq.append((now, port)); self._prune(dq, now)
            distinct = len({p for _, p in dq})
            if distinct >= self.scan_ports_threshold:
                findings.append(Finding("ANO-PORTSCAN", "medium", ["T1046"], src, dst,
                                        f"{distinct} distinct dst ports in {self.window_s}s"))
        # 4) anomaly: host sweep
        dqh = self._hosts[src]; dqh.append((now, dst)); self._prune(dqh, now)
        if len({h for _, h in dqh}) >= self.sweep_hosts_threshold:
            findings.append(Finding("ANO-SWEEP", "medium", ["T1046"], src, dst,
                                    "host sweep across many destinations"))
        # 5) anomaly: brute force
        if ev.get("event") == "auth_fail" or ev.get("outcome") == "auth_fail":
            dqa = self._auth_fail[src]; dqa.append((now, dst)); self._prune(dqa, now)
            if len(dqa) >= self.bruteforce_threshold:
                findings.append(Finding("ANO-BRUTE", "high", ["T1110"], src, dst,
                                        f"{len(dqa)} auth failures in {self.window_s}s"))
        # 6) anomaly: low-jitter beacon (regular callback to one dst)
        key = f"{src}->{dst}"
        dqb = self._beacon[key]; dqb.append((now, 1)); self._prune(dqb, now)
        if len(dqb) >= self.beacon_min_samples:
            times = [t for t, _ in dqb]
            gaps = [t2 - t1 for t1, t2 in zip(times[:-1], times[1:])]
            if len(gaps) >= 3 and statistics.mean(gaps) > 0:
                jitter = statistics.pstdev(gaps) / statistics.mean(gaps)
                if jitter < 0.15:  # very regular = beacon
                    findings.append(Finding("ANO-BEACON", "high", ["T1071", "T1571"], src, dst,
                                            f"regular beacon (jitter={jitter:.2f})"))

        for f in findings:
            f.verdict = self._verdict(f.severity)
        return findings


def _selftest() -> int:
    ok, total = 0, 0
    # signature
    ids = IDSEngine(mode="ips")
    total += 1
    f = ids.inspect({"src_ip": "10.0.0.5", "dst_ip": "185.220.1.9", "dst_port": 443})
    if any(x.rule == "SIG-BADIP" and x.verdict == "DROP" for x in f):
        ok += 1; print("  [PASS] known-bad IP -> DROP")
    else:
        print("  [FAIL] known-bad IP")
    # C2 port
    total += 1
    f = ids.inspect({"src_ip": "10.0.0.5", "dst_ip": "10.0.0.9", "dst_port": 4444})
    if any(x.rule == "SIG-C2PORT" for x in f):
        ok += 1; print("  [PASS] C2 port 4444")
    else:
        print("  [FAIL] C2 port")
    # port scan
    ids2 = IDSEngine(mode="ids", scan_ports_threshold=15)
    scanned = []
    for p in range(20, 40):
        scanned = ids2.inspect({"src_ip": "10.0.0.66", "dst_ip": "10.0.0.9", "dst_port": p, "ts": time.time()})
    total += 1
    if any(x.rule == "ANO-PORTSCAN" for x in scanned):
        ok += 1; print("  [PASS] port scan detected (T1046)")
    else:
        print("  [FAIL] port scan")
    # brute force
    ids3 = IDSEngine(mode="ips", bruteforce_threshold=10)
    bf = []
    for _ in range(11):
        bf = ids3.inspect({"src_ip": "10.0.0.77", "dst_ip": "10.0.0.2", "event": "auth_fail", "ts": time.time()})
    total += 1
    if any(x.rule == "ANO-BRUTE" and x.verdict == "DROP" for x in bf):
        ok += 1; print("  [PASS] brute force -> DROP (T1110)")
    else:
        print("  [FAIL] brute force")
    # beacon
    ids4 = IDSEngine(mode="ids", beacon_min_samples=4, window_s=100)
    be = []
    t0 = 1000.0
    for i in range(6):
        be = ids4.inspect({"src_ip": "10.0.0.88", "dst_ip": "185.10.10.10", "dst_port": 443, "ts": t0 + i * 5})
    total += 1
    if any(x.rule == "ANO-BEACON" for x in be):
        ok += 1; print("  [PASS] C2 beacon detected (low jitter)")
    else:
        print("  [FAIL] beacon")
    # benign
    ids5 = IDSEngine(mode="ips")
    total += 1
    fb = ids5.inspect({"src_ip": "10.0.0.5", "dst_ip": "10.0.0.6", "dst_port": 443})
    if not fb:
        ok += 1; print("  [PASS] benign traffic -> no finding")
    else:
        print("  [FAIL] benign flagged")
    print(f"\nIDS/IPS self-test: {ok}/{total} passed")
    return 0 if ok == total else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Exonerve IDS/IPS engine")
    ap.add_argument("--test", action="store_true")
    ap.add_argument("--mode", choices=["ids", "ips"], default="ids")
    ap.add_argument("--inspect", help="JSON flow event")
    args = ap.parse_args()
    if args.inspect:
        eng = IDSEngine(mode=args.mode)
        print(json.dumps([f.to_dict() for f in eng.inspect(json.loads(args.inspect))], indent=2))
    else:
        sys.exit(_selftest())
