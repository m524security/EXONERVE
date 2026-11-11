#!/usr/bin/env python3
"""
Exonerve :: Backdoor Check  (v3.12 — Incident Response Playbook, BACKDOOR_CHECK stage)
=========================================================================================
After remediation, before declaring an incident closed: has the attacker
left a way back in? This is a point-in-time BASELINE SNAPSHOT + DIFF tool,
not a continuous detector (SSHPersistenceDetector in modern_threats.py
already does continuous SSH-key monitoring — this reuses its exact
file-reading logic rather than re-implementing it, same discipline as
everywhere else in this project).

Covers, read-only:
  - SSH authorized_keys (reuses SSHPersistenceDetector's own path-discovery
    and key-parsing — no second implementation of the same logic)
  - Cron entries (system crontab, /etc/cron.d/*, per-user spool files)
  - Systemd services enabled to start at boot
  - Currently running processes (name/exe/cmdline snapshot)

DESIGN, matching the playbook's human-in-the-loop model explicitly
requested: this class produces FINDINGS. It never decides "clean" on its
own — the playbook stage this feeds (BACKDOOR_CHECK_PENDING ->
BACKDOOR_CHECK_COMPLETE) requires an explicit SOC sign-off after reviewing
whatever this surfaces, whether that's zero findings or fifty.
"""
from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class BackdoorSnapshot:
    timestamp: str
    ssh_keys: Dict[str, List[str]]          # path -> sorted key fingerprints
    cron_entries: Dict[str, List[str]]      # path -> sorted raw entry lines
    startup_services: List[str]             # sorted enabled service names
    running_processes: List[str]            # sorted "pid:name:exe" strings

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp,
            "ssh_keys": self.ssh_keys,
            "cron_entries": self.cron_entries,
            "startup_services": self.startup_services,
            "running_processes": self.running_processes,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "BackdoorSnapshot":
        return cls(timestamp=d["timestamp"], ssh_keys=d["ssh_keys"],
                  cron_entries=d["cron_entries"],
                  startup_services=d["startup_services"],
                  running_processes=d["running_processes"])


class BackdoorCheck:
    def __init__(self,
                cron_dirs: Optional[List[str]] = None,
                cron_spool_dir: str = "/var/spool/cron/crontabs",
                systemd_wants_dir: str = "/etc/systemd/system/multi-user.target.wants"):
        self.cron_dirs = cron_dirs if cron_dirs is not None else ["/etc/cron.d", "/etc/crontab"]
        self.cron_spool_dir = cron_spool_dir
        self.systemd_wants_dir = systemd_wants_dir

    # -- snapshot -----------------------------------------------------------

    def snapshot(self) -> BackdoorSnapshot:
        return BackdoorSnapshot(
            timestamp=_now_iso(),
            ssh_keys=self._snapshot_ssh_keys(),
            cron_entries=self._snapshot_cron(),
            startup_services=self._snapshot_startup_services(),
            running_processes=self._snapshot_processes(),
        )

    def _snapshot_ssh_keys(self) -> Dict[str, List[str]]:
        # Reuses SSHPersistenceDetector's own path-discovery and key-parsing
        # logic rather than re-implementing it — same files, same parsing,
        # one source of truth for "what counts as an authorized_keys entry."
        repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        gp_vm = os.path.join(repo_root, "guest_production_vm")
        if gp_vm not in sys.path:
            sys.path.insert(0, gp_vm)
        from modern_threats import SSHPersistenceDetector

        result: Dict[str, List[str]] = {}
        for path in SSHPersistenceDetector._discover_paths():
            keys = SSHPersistenceDetector._read_keys(path)
            if keys:
                result[path] = sorted(keys)
        return result

    def _snapshot_cron(self) -> Dict[str, List[str]]:
        result: Dict[str, List[str]] = {}
        candidates: List[str] = []
        for entry in self.cron_dirs:
            if os.path.isdir(entry):
                try:
                    candidates.extend(os.path.join(entry, f) for f in os.listdir(entry))
                except OSError:
                    continue
            elif os.path.isfile(entry):
                candidates.append(entry)
        if os.path.isdir(self.cron_spool_dir):
            try:
                candidates.extend(os.path.join(self.cron_spool_dir, f)
                                 for f in os.listdir(self.cron_spool_dir))
            except OSError:
                pass
        for path in candidates:
            lines = self._read_meaningful_lines(path)
            if lines:
                result[path] = sorted(lines)
        return result

    def _snapshot_startup_services(self) -> List[str]:
        if not os.path.isdir(self.systemd_wants_dir):
            return []
        try:
            return sorted(f for f in os.listdir(self.systemd_wants_dir)
                         if f.endswith(".service"))
        except OSError:
            return []

    def _snapshot_processes(self) -> List[str]:
        try:
            import psutil
        except ImportError:
            return []
        out = []
        try:
            for p in psutil.process_iter(["pid", "name", "exe"]):
                out.append(f"{p.info.get('pid')}:{p.info.get('name')}:"
                          f"{p.info.get('exe') or ''}")
        except Exception:
            pass
        return sorted(out)

    @staticmethod
    def _read_meaningful_lines(path: str) -> List[str]:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                return [ln.strip() for ln in f
                       if ln.strip() and not ln.strip().startswith("#")]
        except OSError:
            return []

    # -- diff -----------------------------------------------------------------

    def diff(self, baseline: BackdoorSnapshot, current: BackdoorSnapshot) -> List[Dict]:
        """Returns a list of findings — never decides pass/fail. Every
        finding needs a human to look at it; a diff with zero findings
        still requires explicit SOC sign-off in the playbook, not an
        automatic 'clean' verdict from this function."""
        findings: List[Dict] = []
        findings += self._diff_mapping("ssh_authorized_key", baseline.ssh_keys, current.ssh_keys)
        findings += self._diff_mapping("cron_entry", baseline.cron_entries, current.cron_entries)
        findings += self._diff_list("startup_service", baseline.startup_services,
                                   current.startup_services)
        findings += self._diff_list("running_process", baseline.running_processes,
                                   current.running_processes)
        return findings

    @staticmethod
    def _diff_mapping(category: str, before: Dict[str, List[str]],
                      after: Dict[str, List[str]]) -> List[Dict]:
        findings = []
        for path in sorted(set(before) | set(after)):
            b = set(before.get(path, []))
            a = set(after.get(path, []))
            added = a - b
            removed = b - a
            if added:
                findings.append({"category": category, "change": "added", "path": path,
                                 "entries": sorted(added)})
            if removed:
                findings.append({"category": category, "change": "removed", "path": path,
                                 "entries": sorted(removed)})
        return findings

    @staticmethod
    def _diff_list(category: str, before: List[str], after: List[str]) -> List[Dict]:
        b, a = set(before), set(after)
        findings = []
        added = a - b
        if added:
            findings.append({"category": category, "change": "added",
                             "entries": sorted(added)})
        removed = b - a
        if removed:
            findings.append({"category": category, "change": "removed",
                             "entries": sorted(removed)})
        return findings
