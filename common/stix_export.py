"""
STIX 2.1 bundle export of Exonerve's detection content.

Emits a standards-compliant STIX 2.1 bundle so Exonerve's detections can be
shared with any STIX/TAXII-aware platform (OpenCTI, MISP via the STIX import,
TheHive/Cortex, Sentinel, etc.) — the interchange format the whole threat-intel
ecosystem speaks. Like the ATT&CK Navigator export, this is pure JSON built from
Exonerve's internal maps; no third-party libraries, no live service required.

The bundle contains, per detected technique:
  * attack-pattern  — the MITRE ATT&CK technique, with an external_reference
                      back to attack.mitre.org (so tools resolve it natively)
  * indicator       — Exonerve's detection for it (name + description; the
                      Sigma rule id when one is mapped)
  * relationship    — indicator  --indicates-->  attack-pattern

IDs are deterministic UUIDv5 (namespaced) so re-exporting the same content
yields stable object ids — friendly to platforms that de-duplicate on id.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

try:
    from mitre_attack import TECHNIQUES, TACTICS, _EVENT_MAP
except ImportError:
    from common.mitre_attack import TECHNIQUES, TACTICS, _EVENT_MAP

# Fixed namespace so UUIDv5 ids are stable across runs/machines.
_NS = uuid.UUID("6f4e2a10-7c3b-5d9e-8a21-000000000000")
_NOW = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, kind + ':' + key)}"


def _identity() -> dict:
    ts = _NOW()
    return {
        "type": "identity", "spec_version": "2.1",
        "id": _sid("identity", "exonerve"),
        "created": ts, "modified": ts,
        "name": "Exonerve", "identity_class": "system",
        "description": "Out-of-band, self-healing SOC & blue-team detection platform.",
    }


def _attack_pattern(tid: str, created_by: str) -> dict:
    tech = TECHNIQUES[tid]
    ts = _NOW()
    # sub-technique ids use the T####.### form in the external reference
    return {
        "type": "attack-pattern", "spec_version": "2.1",
        "id": _sid("attack-pattern", tid),
        "created_by_ref": created_by, "created": ts, "modified": ts,
        "name": tech.name,
        "external_references": [{
            "source_name": "mitre-attack",
            "external_id": tid,
            "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
        }],
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack",
             "phase_name": TACTICS.get(t, t).lower().replace(" ", "-")}
            for t in tech.tactics
        ],
    }


def _indicator(tid: str, created_by: str, sigma_id: Optional[str]) -> dict:
    tech = TECHNIQUES[tid]
    ts = _NOW()
    desc = f"Exonerve deterministic detection for {tid} ({tech.name})."
    if sigma_id:
        desc += f" Sigma rule: {sigma_id}."
    return {
        "type": "indicator", "spec_version": "2.1",
        "id": _sid("indicator", tid),
        "created_by_ref": created_by, "created": ts, "modified": ts,
        "name": f"Exonerve detection: {tech.name}",
        "description": desc,
        "indicator_types": ["malicious-activity"],
        "pattern_type": "sigma" if sigma_id else "stix",
        # A minimal valid STIX pattern; the real logic lives in the Sigma rule.
        "pattern": (f"[x-exonerve:technique = '{tid}']"),
        "valid_from": ts,
    }


def _relationship(src: str, rel: str, tgt: str, created_by: str) -> dict:
    ts = _NOW()
    return {
        "type": "relationship", "spec_version": "2.1",
        "id": _sid("relationship", f"{src}|{rel}|{tgt}"),
        "created_by_ref": created_by, "created": ts, "modified": ts,
        "relationship_type": rel,
        "source_ref": src, "target_ref": tgt,
    }


def _detectable_technique_ids() -> List[str]:
    ids = set()
    for tids in _EVENT_MAP.values():
        ids.update(tids)
    return sorted(t for t in ids if t in TECHNIQUES)


def build_bundle(technique_ids: Optional[Iterable[str]] = None,
                 sigma_ids: Optional[Dict[str, str]] = None) -> dict:
    """Assemble a STIX 2.1 bundle for the given techniques (default: all detectable)."""
    sigma_ids = sigma_ids or {}
    tids = list(technique_ids) if technique_ids is not None else _detectable_technique_ids()
    tids = [t for t in tids if t in TECHNIQUES]

    identity = _identity()
    objects: List[dict] = [identity]
    for tid in tids:
        ap = _attack_pattern(tid, identity["id"])
        ind = _indicator(tid, identity["id"], sigma_ids.get(tid))
        rel = _relationship(ind["id"], "indicates", ap["id"], identity["id"])
        objects.extend([ap, ind, rel])

    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid5(_NS, 'exonerve-bundle:' + ','.join(tids))}",
        "objects": objects,
    }


def write_bundle(bundle: dict, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(bundle, fh, indent=2)
    return path


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Export a STIX 2.1 bundle of detections")
    ap.add_argument("--out", default="exonerve_detections.stix.json")
    args = ap.parse_args()
    b = build_bundle()
    write_bundle(b, args.out)
    n_ap = sum(1 for o in b["objects"] if o["type"] == "attack-pattern")
    print(f"Wrote STIX 2.1 bundle: {len(b['objects'])} objects "
          f"({n_ap} techniques) -> {args.out}")
