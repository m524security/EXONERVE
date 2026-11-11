"""
CycloneDX 1.5 SBOM (Software Bill of Materials) generator.

Emits a CycloneDX 1.5 JSON SBOM describing Exonerve and its declared Python
dependencies — the supply-chain artifact enterprise security teams increasingly
require (and that reviewers flagged as missing). Dependency-free: reads the
project's requirements files and, when packages are installed, records their
resolved versions so the SBOM reflects what actually shipped.

Run:  python -m common.sbom  [--out sbom.cdx.json]
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

_ROOT = Path(__file__).resolve().parent.parent
_REQ_FILES = [
    _ROOT / "requirements.txt",
    _ROOT / "host_control_plane" / "requirements.txt",
    _ROOT / "guest_production_vm" / "requirements.txt",
    _ROOT / "blue_team" / "requirements.txt",
]
_SPEC_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*([<>=!~]=?.*)?$")


def _read_version() -> str:
    vf = _ROOT / "VERSION"
    return vf.read_text().strip() if vf.exists() else "0.0.0"


def _installed_version(pkg: str) -> Optional[str]:
    try:
        from importlib import metadata
        return metadata.version(pkg)
    except Exception:
        return None


def _collect_dependencies() -> Dict[str, str]:
    """Map package -> version spec (deduped across all requirements files)."""
    deps: Dict[str, str] = {}
    for f in _REQ_FILES:
        if not f.exists():
            continue
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = _SPEC_RE.match(line)
            if not m:
                continue
            name = m.group(1).lower()
            spec = (m.group(2) or "").strip()
            # keep the most specific spec we've seen
            if name not in deps or (spec and not deps[name]):
                deps[name] = spec
    return deps


def _purl(name: str, version: str) -> str:
    ver = version.lstrip("=") if version else ""
    return f"pkg:pypi/{name}@{ver}" if ver else f"pkg:pypi/{name}"


def build_sbom() -> dict:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    version = _read_version()
    deps = _collect_dependencies()

    components: List[dict] = []
    for name, spec in sorted(deps.items()):
        resolved = _installed_version(name)
        # Prefer the actually-installed version; else the pinned spec version.
        pinned = ""
        m = re.search(r"==\s*([0-9][\w.\-]*)", spec)
        if m:
            pinned = m.group(1)
        ver = resolved or pinned or ""
        comp = {
            "type": "library",
            "bom-ref": f"pkg:pypi/{name}",
            "name": name,
            "version": ver,
            "purl": _purl(name, ver),
            "scope": "required",
        }
        if spec:
            comp["properties"] = [{"name": "requirement-spec", "value": spec}]
        if resolved:
            comp.setdefault("properties", []).append(
                {"name": "resolved", "value": "installed"})
        components.append(comp)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": [{"vendor": "Exonerve", "name": "sbom.py",
                       "version": version}],
            "component": {
                "type": "application",
                "bom-ref": "exonerve",
                "name": "exonerve",
                "version": version,
                "description": "Out-of-band, self-healing SOC & blue-team platform.",
            },
        },
        "components": components,
    }


def write_sbom(sbom: dict, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(sbom, fh, indent=2)
    return path


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Generate a CycloneDX 1.5 SBOM")
    ap.add_argument("--out", default="exonerve.sbom.cdx.json")
    args = ap.parse_args()
    sbom = build_sbom()
    write_sbom(sbom, args.out)
    print(f"Wrote CycloneDX 1.5 SBOM: {len(sbom['components'])} components "
          f"-> {args.out}")
