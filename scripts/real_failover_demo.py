#!/usr/bin/env python3
"""
Real (libvirt) failover demo — dry-run safe, filmable.
Shows the FailoverOrchestrator driving a genuine libvirt backend end-to-end.
On a KVM host, add --live to actually start/stop domains.

    python3 scripts/real_failover_demo.py            # dry-run (prints virsh cmds)
    python3 scripts/real_failover_demo.py --live     # real, on a KVM host
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "host_control_plane"))

from failover_orchestrator import FailoverOrchestrator          # noqa: E402
from libvirt_backend import LibvirtFailoverBackend, build_libvirt_backend  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", action="store_true")
    ap.add_argument("--uri", default="qemu:///system")
    args = ap.parse_args()
    dry = not args.live

    print(f"\n=== Exonerve — REAL libvirt failover ({'LIVE' if args.live else 'dry-run'}) ===\n")

    # 1) hypervisor containment on the compromised VM (real virsh/libvirt)
    hv = build_libvirt_backend(dry_run=dry, uri=args.uri)
    print("[1] Out-of-band incident response on the infected VM (web-vm-01):")
    for r in hv.full_incident_response("web-vm-01"):
        tick = "✓" if r.success else "✗"
        print(f"    {tick} {r.operation:12} {r.message}")

    # 2) business-continuity failover using the REAL libvirt backend
    fob = LibvirtFailoverBackend(uri=args.uri, dry_run=dry)
    orch = FailoverOrchestrator(backend=fob)
    orch.register_service("web-app", vip="10.0.0.100",
                          active_vm="web-vm-01", standby_vms=["web-vm-02"])
    print("\n[2] Business-continuity failover (promote standby → active):")
    result = orch.handle_compromise("web-vm-01")
    print("    " + json.dumps(result, default=str))

    print("\n[3] libvirt action audit trail:")
    for a in hv.actions:
        print(f"    - [{a['mode']}] {a['command']}")
    for a in fob.log:
        print(f"    - failover: {a}")

    if dry:
        print("\n[dry-run] No hypervisor changes were made. Run with --live on a KVM host.")


if __name__ == "__main__":
    main()
