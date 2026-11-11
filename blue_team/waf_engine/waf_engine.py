#!/usr/bin/env python3
"""
Exonerve :: Blue Team Tool — WAF Engine (HTTP request inspection)
=====================================================================
A configuration-driven Web Application Firewall detection layer. It inspects
HTTP request components (URI, query string, headers, body, cookies) against a
curated signature set for the OWASP-relevant attack classes and returns a
verdict (ALLOW / BLOCK) with the matched rule, ATT&CK id, and an anomaly score.

This is DEFENSIVE detection content — it recognizes malicious *request shapes*
so they can be blocked. It contains no exploit or payload; the signatures are
detection regexes (the same approach as the OWASP ModSecurity Core Rule Set).

Design:
  - Rules are data (id, class, ATT&CK, regex, weight, target) — add/tune via config.
  - Scoring is additive with a configurable block threshold (paranoia level),
    so one weak indicator doesn't block but several do.
  - Targets let a rule apply to only the URI, args, headers, body, or cookies.

Usage:
    python3 waf_engine.py --test
    python3 waf_engine.py --inspect '{"uri":"/x","args":"id=1 OR 1=1--"}'
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class WafRule:
    id: str
    attack_class: str
    attack: str            # ATT&CK id
    pattern: str
    weight: int = 5
    targets: tuple = ("uri", "args", "body", "cookies", "headers")
    _rx: Optional[re.Pattern] = field(default=None, repr=False)

    def compiled(self) -> re.Pattern:
        if self._rx is None:
            self._rx = re.compile(self.pattern, re.IGNORECASE)
        return self._rx


# ---- Curated signature set (detection patterns, not payloads) --------------
def default_rules() -> List[WafRule]:
    return [
        # SQL injection
        WafRule("SQLI-1", "sqli", "T1190",
                r"(\bunion\b\s+\bselect\b|\bor\b\s+1\s*=\s*1|;\s*drop\s+table|sleep\s*\(|benchmark\s*\()",
                weight=6, targets=("uri", "args", "body")),
        WafRule("SQLI-2", "sqli", "T1190", r"(--|#|/\*).*(\bor\b|\band\b).*=", weight=3,
                targets=("args", "body")),
        # Cross-site scripting
        WafRule("XSS-1", "xss", "T1190", r"(<script\b|onerror\s*=|onload\s*=|javascript:)",
                weight=5, targets=("uri", "args", "body")),
        WafRule("XSS-2", "xss", "T1190", r"(<img[^>]+src\s*=|document\.cookie|<svg/onload)",
                weight=4, targets=("args", "body")),
        # Path traversal / LFI
        WafRule("LFI-1", "path_traversal", "T1190", r"(\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|boot\.ini)",
                weight=6, targets=("uri", "args")),
        # OS command injection
        WafRule("RCE-1", "cmd_injection", "T1190",
                r"(;\s*(cat|ls|id|whoami|curl|wget)\b|\|\s*(bash|sh)\b|\$\(.*\)|`.*`)",
                weight=6, targets=("uri", "args", "body")),
        # SSRF
        WafRule("SSRF-1", "ssrf", "T1190",
                r"(https?://(127\.0\.0\.1|localhost|169\.254\.169\.254|\[::1\]))",
                weight=5, targets=("uri", "args", "body")),
        # JNDI / Log4Shell-style lookups
        WafRule("JNDI-1", "jndi_injection", "T1190",
                r"\$\{jndi:(ldap|ldaps|rmi|dns|nis|iiop|corba|nds|http):",
                weight=8, targets=("uri", "args", "body", "headers")),
        # Known scanner/user-agent recon
        WafRule("SCAN-1", "scanner", "T1595",
                r"(sqlmap|nikto|nmap|acunetix|nessus|masscan|dirbuster|wpscan)",
                weight=4, targets=("headers",)),
    ]


class WafEngine:
    def __init__(self, rules: Optional[List[WafRule]] = None, block_threshold: int = 5):
        self.rules = rules if rules is not None else default_rules()
        self.block_threshold = block_threshold

    def inspect(self, request: dict) -> dict:
        """request keys: uri, args, body, headers, cookies, src_ip, method.
        Returns verdict dict with matched rules, score, ATT&CK ids."""
        matched: List[dict] = []
        score = 0
        for rule in self.rules:
            rx = rule.compiled()
            for tgt in rule.targets:
                val = request.get(tgt)
                if not val:
                    continue
                text = val if isinstance(val, str) else json.dumps(val)
                if rx.search(text):
                    matched.append({"rule": rule.id, "class": rule.attack_class,
                                    "attack": rule.attack, "target": tgt,
                                    "weight": rule.weight})
                    score += rule.weight
                    break  # one hit per rule is enough
        verdict = "BLOCK" if score >= self.block_threshold else "ALLOW"
        techniques = sorted({m["attack"] for m in matched})
        return {"verdict": verdict, "score": score, "threshold": self.block_threshold,
                "matched": matched, "techniques": techniques,
                "src_ip": request.get("src_ip"), "method": request.get("method"),
                "uri": request.get("uri")}


def _selftest() -> int:
    waf = WafEngine()
    cases = [
        ({"uri": "/products", "args": "id=1 OR 1=1--"}, "BLOCK", "sqli"),
        ({"uri": "/search", "args": "q=<script>alert(1)</script>"}, "BLOCK", "xss"),
        ({"uri": "/download", "args": "file=../../../../etc/passwd"}, "BLOCK", "path_traversal"),
        ({"uri": "/ping", "args": "host=8.8.8.8; cat /etc/passwd"}, "BLOCK", "cmd_injection"),
        ({"uri": "/fetch", "args": "url=http://169.254.169.254/latest/meta-data"}, "BLOCK", "ssrf"),
        ({"uri": "/", "headers": "User-Agent: ${jndi:ldap://x/a}"}, "BLOCK", "jndi_injection"),
        ({"uri": "/", "headers": "User-Agent: sqlmap/1.7"}, "ALLOW", "scanner"),  # single weak signal
        ({"uri": "/home", "args": "page=2", "headers": "User-Agent: Mozilla/5.0"}, "ALLOW", None),
    ]
    ok = 0
    for req, expect_verdict, expect_class in cases:
        r = waf.inspect(req)
        classes = {m["class"] for m in r["matched"]}
        vok = r["verdict"] == expect_verdict
        cok = (expect_class in classes) if expect_class else (len(classes) == 0)
        status = "PASS" if (vok and cok) else "FAIL"
        if vok and cok:
            ok += 1
        print(f"  [{status}] {req.get('uri'):12} -> {r['verdict']:5} score={r['score']:<2} "
              f"{','.join(sorted(classes)) or '(clean)'}")
    print(f"\nWAF self-test: {ok}/{len(cases)} passed")
    return 0 if ok == len(cases) else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Exonerve WAF engine")
    ap.add_argument("--test", action="store_true")
    ap.add_argument("--inspect", help="JSON HTTP request to inspect")
    ap.add_argument("--threshold", type=int, default=5)
    args = ap.parse_args()
    if args.inspect:
        print(json.dumps(WafEngine(block_threshold=args.threshold).inspect(json.loads(args.inspect)), indent=2))
    else:
        sys.exit(_selftest())
