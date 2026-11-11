#!/usr/bin/env python3
"""Console entry point for `exonerve` (installed via pip)."""
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main() -> int:
    argv = sys.argv[1:]
    routes = {
        "verify": ROOT / "verify.py",
        "replay": ROOT / "attack_replay.py",
        "demo": ROOT / "demo.py",
        "blue": ROOT / "blue_team" / "exonerve.py",
    }
    if not argv or argv[0] in ("-h", "--help"):
        print("exonerve <verify|replay|demo|blue|audit-verify|attack-layer> [args...]")
        print("  verify        run the 44-check correctness suite")
        print("  replay        run the ATT&CK attack-replay coverage report")
        print("  demo          run the end-to-end attack->defense story")
        print("  blue          the 27-tool blue-team CLI (e.g. exonerve blue tools)")
        print("  audit-verify  verify the tamper-evident decision audit log")
        print("  attack-layer  export an ATT&CK Navigator layer of detection coverage")
        print("  stix-export   export detections as a STIX 2.1 bundle (OpenCTI/MISP/Sentinel)")
        print("  sbom          generate a CycloneDX 1.5 software bill of materials")
        return 0
    cmd, rest = argv[0], argv[1:]
    if cmd == "audit-verify":
        sys.path.insert(0, str(ROOT))
        from common.audit_log import verify_file
        path = rest[0] if rest else str(ROOT / "host_control_plane" /
                                        "forensics_archive" / "decisions.jsonl")
        rep = verify_file(path)
        status = "INTACT ✓" if rep["ok"] else "TAMPERED ✗"
        print(f"Decision audit log: {status}")
        print(f"  path:    {path}")
        print(f"  entries: {rep['entries']}")
        print(f"  reason:  {rep['reason']}")
        return 0 if rep["ok"] else 1
    if cmd == "sbom":
        sys.path.insert(0, str(ROOT))
        from common.sbom import build_sbom, write_sbom
        out = rest[0] if rest else "exonerve.sbom.cdx.json"
        sbom = build_sbom()
        write_sbom(sbom, out)
        print(f"Wrote CycloneDX 1.5 SBOM ({len(sbom['components'])} components) -> {out}")
        return 0
    if cmd == "stix-export":
        sys.path.insert(0, str(ROOT))
        from common.stix_export import build_bundle, write_bundle
        out = rest[0] if rest else "exonerve_detections.stix.json"
        bundle = build_bundle()
        write_bundle(bundle, out)
        n = sum(1 for o in bundle["objects"] if o["type"] == "attack-pattern")
        print(f"Wrote STIX 2.1 bundle ({len(bundle['objects'])} objects, "
              f"{n} techniques) -> {out}")
        print("Import into OpenCTI / MISP / Sentinel / TheHive (STIX 2.1).")
        return 0
    if cmd == "attack-layer":
        sys.path.insert(0, str(ROOT))
        from common.attack_navigator import coverage_layer, write_layer
        out = rest[0] if rest else "exonerve_attack_layer.json"
        layer = coverage_layer()
        write_layer(layer, out)
        print(f"Wrote ATT&CK Navigator coverage layer "
              f"({len(layer['techniques'])} techniques) -> {out}")
        print("Load at https://mitre-attack.github.io/attack-navigator/ "
              "(Open Existing Layer -> Upload from local)")
        return 0
    target = routes.get(cmd)
    if target is None:
        print(f"unknown command: {cmd}")
        return 2
    sys.argv = [str(target)] + rest
    sys.path.insert(0, str(target.parent))
    runpy.run_path(str(target), run_name="__main__")
    return 0


if __name__ == "__main__":
    sys.exit(main())
