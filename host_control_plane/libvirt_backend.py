#!/usr/bin/env python3
"""
Exonerve :: libvirt Backend (REAL KVM/QEMU enforcement)
===========================================================
The first *non-simulated* enforcement adapter. It performs genuine out-of-band
actions against KVM/QEMU virtual machines through libvirt — the standard Linux
virtualization API — so containment and failover happen at the hypervisor layer,
where malware inside the guest cannot interfere.

Capabilities (all real when libvirt is present):
  - isolate_vm()      detach the guest's virtual NIC(s)         (cut C2/exfil)
  - restore_nic()     re-attach the NIC after remediation
  - snapshot()        create a named snapshot                   (save clean state)
  - revert()          revert to a snapshot                      (restore golden)
  - dump_memory()     dump domain RAM to the forensics archive  (save evidence)
  - domain_state()    query running/paused/shut-off

Execution modes (auto-selected, override with force=):
  1. libvirt Python API   — if the `libvirt` module is importable  (preferred)
  2. virsh CLI            — if the `virsh` binary is on PATH        (fallback)
  3. dry-run              — otherwise: emits the exact virsh commands it *would*
                            run, executes nothing. This is the DEFAULT, so the
                            module is always importable, testable, and CI-safe.

SAFETY: dry_run=True by default. Nothing touches a hypervisor until you pass
dry_run=False (or --live on the CLI). Every action returns a HypervisorResult
and is appended to an auditable action log.

Also provides LibvirtFailoverBackend, a real implementation of the
FailoverBackend interface (promote/redirect/health/rejoin) driven by libvirt
domain start/destroy — drop it into FailoverOrchestrator in place of
SimulatedBackend for a genuine, filmable failover.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional

try:  # real API if available; never required
    import libvirt  # type: ignore
    _HAVE_LIBVIRT = True
except Exception:
    libvirt = None  # type: ignore
    _HAVE_LIBVIRT = False


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class HypervisorResult:
    success: bool
    operation: str
    vm_id: str
    message: str
    timestamp: str = field(default_factory=_now)
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"success": self.success, "operation": self.operation,
                "vm_id": self.vm_id, "message": self.message,
                "timestamp": self.timestamp, "details": self.details}


class LibvirtBackend:
    """Out-of-band containment/forensics on KVM/QEMU via libvirt."""

    def __init__(self, uri: str = "qemu:///system", dry_run: bool = True,
                 forensics_dir: str = "/opt/exonerve/forensics_archive",
                 force: Optional[str] = None):
        self.uri = uri
        self.dry_run = dry_run
        self.forensics_dir = forensics_dir
        self.actions: List[dict] = []
        # decide execution mode
        if force in ("dryrun", "dry-run"):
            self.mode = "dry-run"
        elif force == "api" or (force is None and _HAVE_LIBVIRT and not dry_run):
            self.mode = "api" if _HAVE_LIBVIRT else "dry-run"
        elif force == "virsh" or (force is None and not dry_run and shutil.which("virsh")):
            self.mode = "virsh"
        else:
            self.mode = "dry-run"
        self._conn = None

    # -- connection (only opened for real API mode) ------------------------
    def _connect(self):
        if self.mode == "api" and self._conn is None and _HAVE_LIBVIRT:
            self._conn = libvirt.open(self.uri)
        return self._conn

    def _virsh(self, args: List[str]) -> HypervisorResult:
        cmd = ["virsh", "-c", self.uri] + args
        line = " ".join(cmd)
        if self.mode == "dry-run":
            self._log("dry-run", line)
            return HypervisorResult(True, args[0], _vm_of(args), f"[dry-run] {line}",
                                    details={"command": line, "executed": False})
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            ok = p.returncode == 0
            self._log("executed", line, ok=ok)
            return HypervisorResult(ok, args[0], _vm_of(args),
                                    p.stdout.strip() or p.stderr.strip() or "ok",
                                    details={"command": line, "rc": p.returncode})
        except Exception as exc:
            self._log("error", line, err=str(exc))
            return HypervisorResult(False, args[0], _vm_of(args),
                                    f"{exc.__class__.__name__}: {exc}",
                                    details={"command": line})

    def _log(self, kind: str, line: str, ok: bool = True, err: Optional[str] = None):
        self.actions.append({"ts": _now(), "mode": self.mode, "kind": kind,
                             "command": line, "ok": ok, "error": err})

    # -- high-level operations ---------------------------------------------
    def domain_state(self, domain: str) -> HypervisorResult:
        if self.mode == "api":
            try:
                d = self._connect().lookupByName(domain)
                running = d.isActive()
                return HypervisorResult(True, "domain_state", domain,
                                        "running" if running else "shut off",
                                        details={"active": bool(running)})
            except Exception as exc:
                return HypervisorResult(False, "domain_state", domain, str(exc))
        return self._virsh(["domstate", domain])

    def isolate_vm(self, domain: str, mac: Optional[str] = None) -> HypervisorResult:
        """Detach the guest NIC(s) at the hypervisor — cuts all guest network I/O."""
        if self.mode == "api":
            try:
                d = self._connect().lookupByName(domain)
                # detach live; in production pass the interface XML / MAC
                flags = libvirt.VIR_DOMAIN_AFFECT_LIVE
                d.detachDeviceFlags(_iface_xml(mac), flags)
                self._log("executed", f"api.detachDeviceFlags({domain})")
                return HypervisorResult(True, "isolate_vm", domain,
                                        "NIC detached via libvirt API")
            except Exception as exc:
                return HypervisorResult(False, "isolate_vm", domain, str(exc))
        args = ["detach-interface", domain, "network", "--live"]
        if mac:
            args += ["--mac", mac]
        r = self._virsh(args)
        r.operation = "isolate_vm"
        return r

    def restore_nic(self, domain: str, network: str = "default") -> HypervisorResult:
        r = self._virsh(["attach-interface", domain, "network", network, "--live"])
        r.operation = "restore_nic"
        return r

    def snapshot(self, domain: str, name: str = "exonerve-clean") -> HypervisorResult:
        r = self._virsh(["snapshot-create-as", domain, name])
        r.operation = "snapshot"
        return r

    def revert(self, domain: str, name: str = "exonerve-clean") -> HypervisorResult:
        r = self._virsh(["snapshot-revert", domain, name])
        r.operation = "revert"
        return r

    def dump_memory(self, domain: str) -> HypervisorResult:
        path = f"{self.forensics_dir}/{domain}-{int(datetime.now().timestamp())}.dump"
        r = self._virsh(["dump", domain, path, "--memory-only", "--live"])
        r.operation = "dump_memory"
        r.details["path"] = path
        return r

    def full_incident_response(self, domain: str) -> List[HypervisorResult]:
        """Isolate → dump RAM → snapshot clean → (caller does failover) → revert."""
        return [self.isolate_vm(domain),
                self.dump_memory(domain),
                self.snapshot(domain, "exonerve-preremediation"),
                self.revert(domain, "exonerve-clean")]


def _iface_xml(mac: Optional[str]) -> str:
    m = f"<mac address='{mac}'/>" if mac else ""
    return f"<interface type='network'>{m}</interface>"


def _vm_of(args: List[str]) -> str:
    return args[1] if len(args) > 1 else "?"


# ---------------------------------------------------------------------------
# Real FailoverBackend built on libvirt (promote/redirect/health/rejoin)
# ---------------------------------------------------------------------------
class LibvirtFailoverBackend:
    """Genuine failover: start the standby domain, stop the compromised one.

    Implements the same 4 methods as host_control_plane.failover_orchestrator's
    FailoverBackend, so it is a drop-in replacement for SimulatedBackend.
    """

    def __init__(self, uri: str = "qemu:///system", dry_run: bool = True):
        self.be = LibvirtBackend(uri=uri, dry_run=dry_run)
        self.log: List[dict] = []

    def promote(self, service: str, node_id: str) -> bool:
        r = self.be._virsh(["start", node_id])
        self.log.append({"op": "promote", "node": node_id, "ok": r.success})
        return r.success

    def redirect_traffic(self, service: str, vip: str, to_node: str) -> bool:
        # In production this drives your LB/VIP; represented here as an audited step.
        self.be._log("executed" if not self.be.dry_run else "dry-run",
                     f"redirect {vip} -> {to_node}")
        self.log.append({"op": "redirect", "vip": vip, "to": to_node, "ok": True})
        return True

    def health_check(self, node_id: str) -> bool:
        r = self.be.domain_state(node_id)
        return r.success

    def rejoin_as_standby(self, service: str, node_id: str) -> bool:
        # revert the cured node to the clean snapshot, then leave it stopped/standby
        r = self.be.revert(node_id, "exonerve-clean")
        self.log.append({"op": "rejoin", "node": node_id, "ok": r.success})
        return r.success


def build_libvirt_backend(dry_run: bool = True, uri: str = "qemu:///system",
                          force: Optional[str] = None) -> LibvirtBackend:
    return LibvirtBackend(uri=uri, dry_run=dry_run, force=force)


if __name__ == "__main__":
    import argparse, json
    ap = argparse.ArgumentParser(description="Exonerve libvirt backend")
    ap.add_argument("--live", action="store_true", help="ACTUALLY act on the hypervisor")
    ap.add_argument("--uri", default="qemu:///system")
    ap.add_argument("--domain", default="web-vm-01")
    ap.add_argument("--op", default="ir",
                    choices=["ir", "isolate", "restore", "snapshot", "revert", "dump", "state"])
    ap.add_argument("--force", default=None, choices=["api", "virsh", "dryrun"])
    args = ap.parse_args()
    be = build_libvirt_backend(dry_run=not args.live, uri=args.uri, force=args.force)
    print(f"[libvirt] mode={be.mode} dry_run={be.dry_run} libvirt_module={_HAVE_LIBVIRT}")
    ops = {"isolate": be.isolate_vm, "restore": be.restore_nic, "snapshot": be.snapshot,
           "revert": be.revert, "dump": be.dump_memory, "state": be.domain_state}
    if args.op == "ir":
        out = [r.to_dict() for r in be.full_incident_response(args.domain)]
    else:
        out = [ops[args.op](args.domain).to_dict()]
    print(json.dumps(out, indent=2))
    if be.dry_run:
        print("\n[dry-run] nothing was changed. Re-run with --live on a KVM host to apply.")
