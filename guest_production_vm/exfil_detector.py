#!/usr/bin/env python3
"""
Exonerve :: Data Exfiltration Detector — Passive + Active  (v3.12)
=====================================================================
Ransomware got a graph+entropy-based detector. This is the same design
philosophy applied to exfiltration: don't just watch for "a lot of bytes
went out" (EgressVolumeMonitor already does that) — watch for the SHAPE of
theft. Two independent, complementary modes, as requested:

PASSIVE — access-then-egress correlation
------------------------------------------
Nothing hooks file-open syscalls in a polling agent, so this samples what
psutil CAN see reliably: which sensitive-looking files a process currently
has open, and whether that SAME process then makes an outbound connection
to a destination it has not talked to before. Neither signal alone is
unusual (reading a file: normal; making a connection: normal); the
CORRELATION — sensitive access followed shortly by egress to something new
— is what staged data theft actually looks like, independent of transfer
volume.

ACTIVE — honeytoken / canary files
-------------------------------------
A detector that only watches passively can be waited out. This one also
ACTS: it plants believable-looking decoy files (fake credential exports,
fake customer data) that no legitimate process has any reason to ever open.
Any read of one is a near-zero-false-positive signal — but reliably
detecting a READ (not a write) needs kernel-level visibility polling
mtime/atime doesn't reliably give (many mounts use relatime/noatime). That
is exactly what kernel_telemetry.py's auditd bridge (v3.12) is for: this
module tells you the exact `auditctl -w ... -p r` rule to install, and
consumes the resulting kernel-sourced read events once installed — it does
not modify the live audit rule set itself. Changing a running system's
audit configuration is a deliberate operational action for a human/deploy
script to take, not something a detector silently does.

HONEST LIMITATION, stated plainly: the active mode's detection reliability
is entirely dependent on the honeytoken watch rule actually being installed
in the target environment. Planting the files without installing the
watch rule gives you decoys that look real but generate no signal when
touched — this module surfaces the exact commands needed specifically so
that gap is visible, not silent.
"""
from __future__ import annotations

import os
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

from kernel_telemetry import KernelProcessEvent  # noqa: E402


# ---------------------------------------------------------------------------
# Passive mode — access-then-egress correlation
# ---------------------------------------------------------------------------

SENSITIVE_PATH_MARKERS = (
    "password", "credential", "secret", "confidential", "backup",
    "customer", "financial", "payroll", "ssn", "database", ".sql",
    ".pem", ".key", "id_rsa", ".env", "wallet",
)

ACCESS_TO_EGRESS_WINDOW_S = 120.0   # a connection within this long after
                                     # sensitive access is "shortly after"


def _looks_sensitive(path: str) -> bool:
    lower = path.lower()
    return any(marker in lower for marker in SENSITIVE_PATH_MARKERS)


class ExfilGraphDetector:
    """PASSIVE mode: correlates sensitive file access with subsequent
    egress from the SAME process, independent of transfer volume."""

    def __init__(self, emit, dedupe_window: float = 600.0,
                access_window_s: float = ACCESS_TO_EGRESS_WINDOW_S):
        self._emit = emit
        self.access_window_s = access_window_s
        self._recent_sensitive_access: Dict[int, deque] = defaultdict(
            lambda: deque(maxlen=32))   # pid -> [(ts, path), ...]
        self._known_destinations: Dict[int, Set[str]] = defaultdict(set)  # pid -> {ip}
        self._fired_pids: Dict[int, float] = {}
        self._dedupe_window = dedupe_window

    def record_file_access(self, pid: int, path: str, ts: Optional[float] = None) -> None:
        if not _looks_sensitive(path):
            return
        ts = ts if ts is not None else time.time()
        self._recent_sensitive_access[pid].append((ts, path))

    def evaluate_connection(self, pid: int, proc_name: str, dest_ip: str,
                            ts: Optional[float] = None) -> Optional[Dict]:
        """Call once per observed outbound connection. Returns a finding if
        this connection follows recent sensitive-file access by the SAME
        process to a destination it hasn't talked to before."""
        ts = ts if ts is not None else time.time()
        accesses = self._recent_sensitive_access.get(pid)
        if not accesses:
            self._known_destinations[pid].add(dest_ip)
            return None

        recent = [(a_ts, path) for a_ts, path in accesses
                 if ts - a_ts <= self.access_window_s]
        if not recent:
            self._known_destinations[pid].add(dest_ip)
            return None

        is_new_destination = dest_ip not in self._known_destinations[pid]
        self._known_destinations[pid].add(dest_ip)
        if not is_new_destination:
            return None   # a process's ROUTINE destination isn't a signal

        if ts - self._fired_pids.get(pid, 0.0) < self._dedupe_window:
            return None
        self._fired_pids[pid] = ts

        paths = sorted({p for _, p in recent})
        detail = {
            "reason": "sensitive_access_then_new_egress",
            "pid": pid, "process": proc_name, "destination": dest_ip,
            "accessed_paths": paths[:10],
            "message": (f"{proc_name} (pid {pid}) opened sensitive-looking "
                       f"file(s) ({', '.join(paths[:3])}) then connected to "
                       f"a destination it has not talked to before "
                       f"({dest_ip}) within {self.access_window_s:.0f}s — "
                       f"consistent with staged data exfiltration, "
                       f"independent of transfer volume"),
        }
        self._emit("exfil_graph", "critical", detail)
        return detail

    def scan(self) -> List[Dict]:
        """Poll-mode entry point: samples open files + connections per
        process via psutil. Best-effort — a process that opens and closes
        a file between polls is invisible to this path (the honest
        limitation of polling); pairing this with kernel_telemetry's
        auditd/Sysmon `paths` data closes that gap where available."""
        if psutil is None:
            return []
        findings = []
        now = time.time()
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                name = proc.info["name"] or "?"
                for f in proc.open_files():
                    self.record_file_access(pid, f.path, now)
                for conn in proc.connections(kind="inet"):
                    if conn.status == "ESTABLISHED" and conn.raddr:
                        result = self.evaluate_connection(pid, name, conn.raddr.ip, now)
                        if result:
                            findings.append(result)
            except (psutil.NoSuchProcess, psutil.AccessDenied, Exception):
                continue
        return findings

    def record_kernel_event(self, event: KernelProcessEvent) -> None:
        """Feed a kernel_telemetry.py event (auditd/Sysmon) into the same
        access-tracking this detector already does from psutil — same
        detector, richer/more-reliable source when available."""
        if event.pid is None:
            return
        for path in event.paths:
            self.record_file_access(event.pid, path, time.time())


# ---------------------------------------------------------------------------
# Active mode — honeytoken / canary files
# ---------------------------------------------------------------------------

DEFAULT_LURE_NAMES = [
    "passwords_export.xlsx",
    "customer_database_backup.sql",
    "aws_credentials.bak",
    "payroll_2026_confidential.csv",
    "ssh_private_key_backup.pem",
]


class HoneytokenManager:
    """ACTIVE mode: plants believable decoy files and tells the operator
    exactly what's needed to make reads on them reliably detectable."""

    def __init__(self, target_dir: str, lure_names: Optional[List[str]] = None):
        self.target_dir = target_dir
        self.lure_names = lure_names or list(DEFAULT_LURE_NAMES)
        self.planted_paths: List[str] = []

    def plant(self) -> List[str]:
        """Write the decoy files. Idempotent: re-running touches existing
        ones rather than duplicating.

        v3.12 fix — found and disclosed the same day it shipped: an earlier
        version wrote content that literally said "DECOY FILE — planted by
        Exonerve" inside the file. Anyone reading contents before deciding
        what to exfiltrate (rather than grabbing by filename alone) would
        spot that instantly and avoid it, defeating the whole mechanism.
        Content is now plausible-looking with no self-identifying marker —
        the fact that a file is bait lives only in this object's
        `planted_paths`, never inside the file itself.
        """
        os.makedirs(self.target_dir, exist_ok=True)
        planted = []
        for name in self.lure_names:
            path = os.path.join(self.target_dir, name)
            if not os.path.exists(path):
                with open(path, "w", encoding="utf-8") as f:
                    f.write(self._plausible_content(name))
            planted.append(path)
        self.planted_paths = planted
        return planted

    @staticmethod
    def _plausible_content(name: str) -> str:
        """Content that looks like a real, boring internal document — no
        wording anywhere that would tip off someone who opens it before
        deciding whether to take it."""
        lower = name.lower()
        if "password" in lower or "credential" in lower:
            return ("username,password,system\n"
                   "svc_backup,B4ckup!2025,fileserver01\n"
                   "svc_monitor,M0nitor#Pass,nagios-prod\n")
        if "sql" in lower or "database" in lower:
            return ("-- customer table dump, generated nightly\n"
                   "INSERT INTO customers (id,name,email) VALUES\n"
                   "(1001,'J. Rivera','jrivera@example.com'),\n"
                   "(1002,'A. Chen','achen@example.com');\n")
        if "aws" in lower or "credential" in lower:
            return ("[default]\naws_access_key_id = AKIAEXAMPLE00000000\n"
                   "aws_secret_access_key = wJalrXUtnFEMIEXAMPLEKEYvalueONLY\n")
        if "payroll" in lower:
            return ("employee_id,name,salary\n1001,J. Rivera,74000\n"
                   "1002,A. Chen,81000\n")
        if "pem" in lower or "key" in lower:
            return ("-----BEGIN RSA PRIVATE KEY-----\n"
                   "MIIEpQIBAAKCAQEAsampleplaceholdervalueNOTaRealKeyXYZ==\n"
                   "-----END RSA PRIVATE KEY-----\n")
        return "internal document\n"

    def auditctl_watch_commands(self) -> List[str]:
        """The exact commands needed to make reads on these files reliably
        detectable via the kernel audit subsystem. NOT executed by this
        module — installing an audit watch rule needs root and is a
        deliberate operational step, not something a detector does to a
        live system on its own."""
        return [f'auditctl -w "{p}" -p r -k exonerve_honeytoken_read'
               for p in self.planted_paths]

    def check_kernel_events(self, events: List[KernelProcessEvent]) -> List[Dict]:
        """Given already-parsed kernel telemetry (see kernel_telemetry.py),
        flag any access to a planted honeytoken path. Near-zero false-
        positive signal BY DESIGN — nothing legitimate has a reason to
        touch a file named 'passwords_export.xlsx' that this agent
        invented five minutes ago."""
        if not self.planted_paths:
            return []
        planted_set = set(self.planted_paths)
        findings = []
        for evt in events:
            hit_paths = [p for p in evt.paths if p in planted_set]
            if not hit_paths:
                continue
            findings.append({
                "reason": "honeytoken_accessed",
                "pid": evt.pid, "process": evt.comm, "paths": hit_paths,
                "source": evt.source,
                "message": (f"process {evt.comm or '?'} (pid {evt.pid}) accessed "
                           f"planted honeytoken file(s) {', '.join(hit_paths)} — "
                           f"no legitimate process has a reason to do this"),
            })
        return findings


class HoneytokenDetector:
    """Wires HoneytokenManager's kernel-event check into this project's
    standard emit(event_type, severity, details) sensor interface, so it
    plugs into ModernThreatSuite the same way every other v3.9/v3.10
    detector does."""

    def __init__(self, emit, manager: HoneytokenManager, dedupe_window: float = 60.0):
        self._emit = emit
        self.manager = manager
        self._last_fire: Dict[str, float] = {}
        self._dedupe_window = dedupe_window

    def scan(self, kernel_events: List[KernelProcessEvent]) -> List[Dict]:
        findings = self.manager.check_kernel_events(kernel_events)
        emitted = []
        now = time.time()
        for finding in findings:
            key = f"{finding['pid']}:{','.join(finding['paths'])}"
            if now - self._last_fire.get(key, 0.0) < self._dedupe_window:
                continue
            self._last_fire[key] = now
            self._emit("honeytoken_accessed", "critical", finding)
            emitted.append(finding)
        return emitted
