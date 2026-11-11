#!/usr/bin/env python3
r"""
Exonerve :: Sigma-Compatible Detection Engine
==================================================
Loads detection rules in the Sigma format (https://sigmahq.io) and matches them
against Exonerve telemetry events. Sigma is the open, vendor-neutral standard
for SIEM detection rules — being compatible with it means analysts can drop in
community rules and Exonerve's own rules use a format the whole industry knows.

SUPPORTED SIGMA SUBSET (faithful to the spec, not the whole thing):
  - title, id, status, description, author, level, tags  (metadata, incl. ATT&CK tags)
  - logsource                                            (informational filter)
  - detection:
      <selection blocks>          dict of {field|modifier: value|list}
      condition: boolean over selection names
                 supports: and / or / not / parentheses / "1 of them" / "all of them"
  - field value modifiers: |contains |startswith |endswith |re |all
  - a list of values on a field = OR; multiple fields in a selection = AND

NOT supported (documented honestly): aggregations (count() by ...),
near/temporal correlation, and field-name backends. Those need a stateful SIEM;
this engine does single-event matching, which covers the rule set we ship.

Usage:
    python3 sigma_engine.py --list
    python3 sigma_engine.py --test
    python3 sigma_engine.py --match '{"event_type":"crypto_spike","details":{}}'
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

# Make the repo root importable so `common.*` resolves when this tool is run
# directly as a script (as blue_team/exonerve.py does), not only under pytest.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from common.safe_eval import safe_eval_bool  # noqa: E402

try:
    import yaml
    _HAVE_YAML = True
except Exception:
    _HAVE_YAML = False

RULES_DIR = Path(__file__).parent / "rules"


# ---------------------------------------------------------------------------
# Field matching with Sigma modifiers
# ---------------------------------------------------------------------------

def _get_field(event: dict, field_name: str) -> Any:
    """Resolve a (possibly dotted) field path against the event dict."""
    cur: Any = event
    for part in field_name.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def _apply_windash(s: str) -> List[str]:
    """Sigma |windash: match both '-' and '/' (and unicode dashes) as option prefixes."""
    variants = {s}
    for dash in ("-", "/", "\u2013", "\u2014"):
        for other in ("-", "/"):
            if dash in s:
                variants.add(s.replace(dash, other))
    return list(variants)


def _cidr_match(actual: str, cidr: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(actual.strip()) in ipaddress.ip_network(cidr, strict=False)
    except (ValueError, TypeError):
        return False


def _match_value(actual: Any, expected: Any, modifier: Optional[str]) -> bool:
    # Modifiers can be compound, e.g. 'contains|all' or 'base64offset|contains'.
    mods = [m.strip() for m in (modifier.split("|") if modifier else []) if m.strip()]

    # 'exists' is a presence test, independent of value.
    if "exists" in mods:
        want = bool(expected) if isinstance(expected, bool) else str(expected).lower() != "false"
        return (actual is not None) == want

    if actual is None:
        return False

    cased = "cased" in mods                       # case-sensitive match
    a = str(actual)

    # Numeric comparisons.
    for op, fn in (("lt", lambda x, y: x < y), ("lte", lambda x, y: x <= y),
                   ("gt", lambda x, y: x > y), ("gte", lambda x, y: x >= y)):
        if op in mods:
            try:
                return fn(float(actual), float(expected))
            except (TypeError, ValueError):
                return False

    # CIDR network membership.
    if "cidr" in mods:
        return _cidr_match(a, str(expected))

    # Regex.
    if "re" in mods:
        try:
            flags = 0 if cased else re.IGNORECASE
            return re.search(str(expected), a, flags) is not None
        except re.error:
            return False

    e = str(expected)

    # base64 / base64offset: the expected plaintext is matched against base64 data.
    if "base64" in mods or "base64offset" in mods:
        import base64 as _b64
        try:
            encs = {_b64.b64encode(e.encode()).decode()}
            if "base64offset" in mods:
                for pad in (b"  ", b" "):   # offset variants
                    encs.add(_b64.b64encode(pad + e.encode()).decode())
            hay = a if cased else a.lower()
            return any((enc if cased else enc.lower()) in hay for enc in encs)
        except Exception:
            return False

    # windash: expand '-'/'/'/unicode-dash variants of the expected value.
    candidates = _apply_windash(e) if "windash" in mods else [e]

    def _cmp(hay: str, needle: str) -> bool:
        if not cased:
            hay, needle = hay.lower(), needle.lower()
        if "contains" in mods:
            return needle in hay
        if "startswith" in mods:
            return hay.startswith(needle)
        if "endswith" in mods:
            return hay.endswith(needle)
        return hay == needle

    # Numeric exact tolerance when no string modifier is present.
    if not any(m in mods for m in ("contains", "startswith", "endswith")) \
            and isinstance(expected, (int, float)) and not isinstance(expected, bool):
        try:
            return float(actual) == float(expected)
        except (TypeError, ValueError):
            return False

    return any(_cmp(a, c) for c in candidates)


def _match_field(event: dict, key: str, value: Any) -> bool:
    """Match one 'field|modifier: value(s)' entry from a selection."""
    if "|" in key:
        field_name, modifier = key.split("|", 1)
        modifier = modifier.strip()
    else:
        field_name, modifier = key, None

    actual = _get_field(event, field_name)

    # 'all' means every value in the list must match (AND); otherwise list = OR.
    if isinstance(value, list):
        mods = [m.strip() for m in (modifier.split("|") if modifier else [])]
        if "all" in mods:
            inner = "|".join(m for m in mods if m != "all") or None
            return all(_match_value(actual, v, inner) for v in value)
        return any(_match_value(actual, v, modifier) for v in value)
    return _match_value(actual, value, modifier)


def _match_selection(event: dict, selection: Any) -> bool:
    """A selection is a dict (AND of fields) or a list of dicts (OR)."""
    if isinstance(selection, list):
        return any(_match_selection(event, s) for s in selection)
    if isinstance(selection, dict):
        return all(_match_field(event, k, v) for k, v in selection.items())
    return False


# ---------------------------------------------------------------------------
# Condition evaluation (boolean over selection names)
# ---------------------------------------------------------------------------

def _eval_condition(condition: str, results: Dict[str, bool]) -> bool:
    """
    Evaluate a Sigma condition string against a map of {selection_name: bool}.
    Supports and/or/not/parens, 'all of them', '1 of them', 'all of selection*'.
    """
    cond = condition.strip()

    # Expand 'X of them' / 'X of selection*' shortcuts.
    def _names(prefix: Optional[str]) -> List[str]:
        if prefix is None:
            return list(results.keys())
        return [n for n in results if n.startswith(prefix)]

    # 'all of them' / 'all of <prefix>*'
    m = re.fullmatch(r"all of (them|[\w]+\*)", cond)
    if m:
        tok = m.group(1)
        names = _names(None) if tok == "them" else _names(tok[:-1])
        return all(results.get(n, False) for n in names) and bool(names)
    # '1 of them' / 'N of them' / '1 of <prefix>*'
    m = re.fullmatch(r"(\d+) of (them|[\w]+\*)", cond)
    if m:
        need = int(m.group(1)); tok = m.group(2)
        names = _names(None) if tok == "them" else _names(tok[:-1])
        return sum(1 for n in names if results.get(n, False)) >= need

    # General boolean expression: replace selection names with True/False.
    # Tokenise on words/parentheses; keep and/or/not as Python operators.
    def repl(token: str) -> str:
        t = token.strip()
        if t in ("and", "or", "not", "(", ")"):
            return t
        if t in results:
            return "True" if results[t] else "False"
        # 'of', 'them', 'all', stray words -> leave for safety as False
        if t in ("True", "False"):
            return t
        return "False"

    tokens = re.findall(r"\(|\)|\w+\*?|\S", cond)
    expr = " ".join(repl(t) for t in tokens)
    # Evaluate via the no-eval safe parser (booleans + parens only here).
    try:
        return safe_eval_bool(expr)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Rule model
# ---------------------------------------------------------------------------

@dataclass
class SigmaRule:
    title: str
    id: str
    level: str
    detection: dict
    description: str = ""
    tags: List[str] = field(default_factory=list)
    logsource: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)

    @property
    def attack_techniques(self) -> List[str]:
        """Extract ATT&CK technique IDs from Sigma tags (attack.t1486 -> T1486)."""
        out = []
        for t in self.tags:
            tl = t.lower()
            m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", tl)
            if m:
                out.append(m.group(1).upper())
        return out

    def match(self, event: dict) -> bool:
        det = self.detection
        condition = det.get("condition", "")
        results = {name: _match_selection(event, sel)
                   for name, sel in det.items() if name != "condition"}
        if not condition:
            # No explicit condition: AND of all selections.
            return all(results.values()) and bool(results)
        return _eval_condition(condition, results)

    def to_dict(self) -> dict:
        return {"title": self.title, "id": self.id, "level": self.level,
                "tags": self.tags, "attack": self.attack_techniques}


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class SigmaEngine:
    def __init__(self):
        self.rules: List[SigmaRule] = []

    def load_dir(self, path: Path = RULES_DIR) -> int:
        if not _HAVE_YAML:
            raise RuntimeError("PyYAML not installed — cannot load Sigma rules")
        count = 0
        for f in sorted(path.glob("*.yml")) + sorted(path.glob("*.yaml")):
            try:
                doc = yaml.safe_load(f.read_text(encoding="utf-8"))
                if not doc or "detection" not in doc:
                    continue
                self.rules.append(SigmaRule(
                    title=doc.get("title", f.stem),
                    id=str(doc.get("id", f.stem)),
                    level=doc.get("level", "medium"),
                    detection=doc["detection"],
                    description=doc.get("description", ""),
                    tags=doc.get("tags", []) or [],
                    logsource=doc.get("logsource", {}) or {},
                    raw=doc,
                ))
                count += 1
            except Exception as e:
                print(f"[warn] failed to load {f.name}: {e}", file=sys.stderr)
        return count

    def evaluate(self, event: dict) -> List[SigmaRule]:
        """Return all rules that fire for a single event."""
        return [r for r in self.rules if r.match(event)]

    def load_community_rules(self, path, recursive: bool = True) -> dict:
        """Ingest official SigmaHQ community rules from a folder tree.

        Point this at a clone of https://github.com/SigmaHQ/sigma (e.g. the
        ``rules/`` directory) to load real, field-level detections instead of
        only the bundled set. Returns a compatibility report so you can see
        exactly how many community rules this engine accepts.
        """
        if not _HAVE_YAML:
            raise RuntimeError("PyYAML not installed — cannot load Sigma rules")
        from pathlib import Path as _P
        root = _P(path)
        globber = root.rglob if recursive else root.glob
        files = sorted(globber("*.yml")) + sorted(globber("*.yaml"))
        report = {"scanned": 0, "loaded": 0, "skipped": 0,
                  "no_detection": 0, "parse_error": 0, "errors": []}
        for f in files:
            report["scanned"] += 1
            try:
                doc = yaml.safe_load(f.read_text(encoding="utf-8"))
            except Exception as e:
                report["parse_error"] += 1
                report["errors"].append(f"{f.name}: parse: {e}")
                continue
            if not isinstance(doc, dict) or "detection" not in doc:
                report["no_detection"] += 1
                continue
            try:
                rule = SigmaRule(
                    title=doc.get("title", f.stem),
                    id=str(doc.get("id", f.stem)),
                    level=doc.get("level", "medium"),
                    detection=doc["detection"],
                    description=doc.get("description", ""),
                    tags=doc.get("tags", []) or [],
                    logsource=doc.get("logsource", {}) or {},
                    raw=doc,
                )
                # smoke-test the condition parses against an empty event
                rule.match({})
                self.rules.append(rule)
                report["loaded"] += 1
            except Exception as e:
                report["skipped"] += 1
                report["errors"].append(f"{f.name}: {e}")
        return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Exonerve Sigma-compatible engine")
    ap.add_argument("--list", action="store_true", help="list loaded rules")
    ap.add_argument("--test", action="store_true", help="run built-in match tests")
    ap.add_argument("--match", metavar="JSON", help="match a single event (JSON)")
    ap.add_argument("--rules-dir", default=str(RULES_DIR))
    args = ap.parse_args()

    eng = SigmaEngine()
    n = eng.load_dir(Path(args.rules_dir))
    print(f"Loaded {n} Sigma rule(s) from {args.rules_dir}")

    if args.list:
        for r in eng.rules:
            print(f"  [{r.level:8}] {r.title:42} {','.join(r.attack_techniques)}")

    if args.match:
        ev = json.loads(args.match)
        fired = eng.evaluate(ev)
        if fired:
            for r in fired:
                print(f"  FIRED: {r.title}  ({','.join(r.attack_techniques)})")
        else:
            print("  No rules matched.")

    if args.test:
        tests = [
            ({"event_type": "crypto_spike", "severity": "critical", "details": {"reason": "ransomware_crypto_spike"}}, True),
            ({"event_type": "shadow", "details": {"reason": "backup_destruction_detected"}}, True),
            ({"event_type": "process", "details": {"reason": "web_server_spawned_shell"}}, True),
            ({"event_type": "network", "details": {"dest_port": 4444}}, True),
            ({"event_type": "heartbeat", "details": {}}, False),
        ]
        ok = 0
        for ev, expect_fire in tests:
            fired = eng.evaluate(ev)
            got = len(fired) > 0
            status = "PASS" if got == expect_fire else "FAIL"
            if got == expect_fire:
                ok += 1
            names = ",".join(r.attack_techniques[0] if r.attack_techniques else r.title for r in fired)
            print(f"  [{status}] {ev['event_type']:14} fired={got:<5} ({names})")
        print(f"\n  {ok}/{len(tests)} match tests passed")


if __name__ == "__main__":
    main()
