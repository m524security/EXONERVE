#!/usr/bin/env python3
"""
Exonerve :: Sentry Agent  (v2 — secured + crypto-spike aware)
=================================================================
Runs silently inside the Guest Production VM (VLAN 10).
Monitors filesystem entropy, a rolling CRYPTOGRAPHIC SPIKE MAP (ransomware),
process lineage, backup-destruction commands, and network sockets.

Transmits AUTHENTICATED, replay-resistant telemetry to the Host Control Plane
via egress-only TCP. ZERO listening ports. Read-only observability posture.

What changed from v1 (and why):
  - Transport upgraded from static-key XOR to the shared SecureChannel
    (AES-256-GCM or HMAC-AEAD, per-agent keys, replay + identity binding).
  - Added CryptographicSpikeDetector: the "crypto map" the design called for —
    it tracks the RATE and VARIANCE of high-entropy writes and fires a dedicated
    `crypto_spike` event the moment encryption behaviour deviates from baseline.
  - Backup-destruction detection now also covers Linux/macOS, not just Windows.
  - Heartbeat carries an agent self-attestation (monotonic seq) so the
    controller's watchdog can tell "VM quiet because idle" from "agent was
    killed" (malware's first move).

Usage:
    python3 sentry_agent.py --target-dir /home --controller-host 192.168.20.1
"""

import argparse
import math
import os
import platform
import socket
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import psutil

# Optional: event-driven filesystem monitoring (inotify on Linux via
# watchdog, ReadDirectoryChangesW on Windows, FSEvents on macOS). Falls back
# to the original polling walk if absent or if the underlying filesystem does
# not support recursive watches (some network mounts, some container overlay
# filesystems) — the agent never hard-requires this the same way it never
# hard-requires `cryptography` for the secure channel.
try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    WATCHDOG_AVAILABLE = True
except Exception:  # pragma: no cover - exercised via monkeypatch in tests
    FileSystemEventHandler = object  # type: ignore
    Observer = None  # type: ignore
    WATCHDOG_AVAILABLE = False

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
# Also expose this directory so the agent works when loaded directly by a
# spec loader (verify.py) as well as when run as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent))
from common.secure_channel import SecureSender, load_master_secret  # noqa: E402
from ransomware_sensors import (  # noqa: E402
    BaselineStore, EntropyTransitionTracker, ExtensionRenameDetector,
    EsxiEncryptionDetector, SlowBurnDetector, EgressVolumeMonitor,
    attribute_writers,
)
from modern_threats import ModernThreatSuite  # noqa: E402

# ---------------------------------------------------------------------------
# Silent diagnostics: the agent must NEVER print to a TTY an attacker can see,
# but swallowing errors with no record makes debugging impossible. Compromise:
# log to a local rotating-ish file only. Failures here are themselves ignored
# (logging must never crash or expose the agent).
# ---------------------------------------------------------------------------
_AGENT_LOG_PATH = os.environ.get("EXONERVE_AGENT_LOG",
                                 os.path.join(os.path.dirname(__file__), "sentry_agent.log"))


def _agent_log(message: str) -> None:
    try:
        from datetime import datetime, timezone
        line = f"{datetime.now(timezone.utc).isoformat()} {message}\n"
        with open(_AGENT_LOG_PATH, "a", encoding="utf-8") as fh:
            fh.write(line)
    except Exception:
        pass  # logging must never break the agent

# ---------------------------------------------------------------------------
# Configuration defaults
# ---------------------------------------------------------------------------
DEFAULT_CONTROLLER_HOST = "192.168.20.1"
DEFAULT_CONTROLLER_PORT = 9999
DEFAULT_TARGET_DIR = "/home"
DEFAULT_ENTROPY_THRESHOLD = 7.2
DEFAULT_POLL_INTERVAL = 2.0
DEFAULT_ENTROPY_WINDOW = 30
DEFAULT_VELOCITY_THRESHOLD = 10

CRYPTO_BASELINE_WINDOW = 300      # seconds of history that forms the baseline
CRYPTO_SPIKE_WINDOW = 15          # recent window compared against baseline
CRYPTO_SPIKE_MIN_FILES = 6        # min recent high-entropy writes to consider
CRYPTO_SPIKE_SIGMA = 3.0          # std-devs above baseline that counts as a spike

SUSPICIOUS_LINEAGE: Dict[str, Set[str]] = {
    "nginx":    {"bash", "sh", "cmd.exe", "powershell.exe", "python", "python3", "perl", "ruby"},
    "apache2":  {"bash", "sh", "cmd.exe", "powershell.exe", "python", "python3"},
    "httpd":    {"bash", "sh", "cmd.exe", "powershell.exe", "python", "python3"},
    "iis":      {"cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe"},
    "tomcat":   {"bash", "sh", "cmd.exe", "powershell.exe"},
    "php-fpm":  {"bash", "sh", "cmd.exe"},
    "node":     {"bash", "sh", "cmd.exe", "powershell.exe"},
    "java":     {"bash", "sh", "cmd.exe", "powershell.exe"},
    "svchost":  {"cmd.exe", "powershell.exe", "wscript.exe"},
}

# bandit flags any "/tmp/"-containing string as B108 (insecure temp-file
# usage) — a false positive here. These are DETECTION SIGNATURES this agent
# watches process exe/cmdline paths against, not locations this code writes
# to. Verified via bandit run, not assumed; see CHANGELOG.md v3.13.
SUSPICIOUS_PATHS_LINUX = {"/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/"}  # nosec B108
SUSPICIOUS_PATHS_WIN = {"\\appdata\\local\\temp\\", "\\windows\\temp\\", "\\users\\public\\"}  # nosec B108

KNOWN_BROWSER_NAMES = {"chrome", "chromium", "firefox", "brave", "edge", "msedge",
                       "opera", "safari", "vivaldi", "iridium"}

SHADOW_COMMANDS = {
    "vssadmin delete shadows", "wmic shadowcopy delete",
    "bcdedit /set {default} recoveryenabled no", "wbadmin delete catalog",
    "diskshadow /s",
}
UNIX_BACKUP_DESTRUCTION = {
    "rm -rf /var/backups", "rm -rf /backup", "rm -rf /snap",
    "btrfs subvolume delete", "zfs destroy", "tmutil deletelocalsnapshots",
    "rm -rf .snapshots", "shred ",
}


@dataclass
class TelemetryEvent:
    vm_id:       str
    timestamp:   str
    event_type:  str
    severity:    str
    score_delta: int
    details:     dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Authenticated telemetry transmitter
# ---------------------------------------------------------------------------

class TelemetryTunnel:
    def __init__(self, host: str, port: int, sender: SecureSender, vm_id: str):
        self.host = host
        self.port = port
        self.sender = sender
        self.vm_id = vm_id
        self._queue: deque = deque(maxlen=500)
        # Separate retry buffer for events that failed to send. Kept distinct from
        # the live queue so a controller outage can NEVER push newer events off the
        # end of the main queue (the old appendleft() bug). Retries are drained
        # first on the next flush so ordering is preserved.
        self._retry: deque = deque(maxlen=2000)
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sender_loop, daemon=True, name="TelemetryTunnel")

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def enqueue(self, event: TelemetryEvent):
        with self._lock:
            self._queue.append(asdict(event))

    def _sender_loop(self):
        while not self._stop.is_set():
            batch = []
            with self._lock:
                # Drain retries first (oldest unsent), then live events.
                while self._retry:
                    batch.append(self._retry.popleft())
                while self._queue:
                    batch.append(self._queue.popleft())
            if batch:
                self._transmit(batch)
            time.sleep(1.0)

    def _transmit(self, events: list):
        payload = {"vm_id": self.vm_id, "batch": events}
        try:
            frame = self.sender.seal(payload)
            wire = struct.pack(">I", len(frame)) + frame
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(5.0)
                s.connect((self.host, self.port))
                s.sendall(wire)
        except Exception as exc:
            # Re-queue into the dedicated retry buffer (append=keep chronological
            # order; it is drained left-first next cycle). The agent stays silent
            # to any attacker on the box — failures go only to a local file.
            with self._lock:
                for e in events:
                    self._retry.append(e)
            _agent_log(f"telemetry send failed ({exc.__class__.__name__}: {exc}); "
                       f"{len(events)} event(s) buffered for retry")


# ---------------------------------------------------------------------------
# Shannon entropy
# ---------------------------------------------------------------------------

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = defaultdict(int)
    for byte in data:
        freq[byte] += 1
    n = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


# v3.10 fix — see DEFENSE_GUIDE.md §2.1 "sparse / interior-block encryption".
# A head-only sample is blind to ransomware that deliberately leaves the
# first bytes of a file untouched (several real families do exactly this to
# defeat head-only entropy checks). Files comfortably larger than one sample
# chunk are now additionally sampled in the middle and at the tail.
SPARSE_SAMPLE_SIZE_MULTIPLIER = 4   # only multi-region-sample files clearly
                                     # bigger than a single head-only chunk


def file_entropy(path: str, sample_bytes: int = 65536) -> Optional[float]:
    """Shannon entropy of a representative sample of the file.

    For small files (<= sample_bytes * SPARSE_SAMPLE_SIZE_MULTIPLIER) this is
    unchanged from earlier versions: one head read of up to `sample_bytes`.

    For larger files we split the same overall byte budget across three
    regions — head, middle, tail — and return the HIGHEST entropy of the
    three. Ransomware that encrypts only the interior or only the tail of a
    file (to keep a head-only entropy check in the plaintext band) still
    trips the ciphertext band via whichever region it actually touched.

    HONEST LIMITATION: this is still point-sampling, not a full-file scan.
    An attacker who scatters ciphertext blocks finely enough to land between
    all three sampled windows would still evade this. That residual gap is
    documented in DEFENSE_GUIDE.md as ACCEPTED — sampling three fixed points
    closes the "encrypt everything except the header" case, not sparse
    encryption at arbitrary, sub-chunk granularity.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return None

    try:
        with open(path, "rb") as f:
            if size <= sample_bytes * SPARSE_SAMPLE_SIZE_MULTIPLIER:
                return shannon_entropy(f.read(sample_bytes))

            # Keep the total bytes read close to the original single-chunk
            # budget rather than tripling I/O across the whole monitored
            # tree: each region gets a third of the sample budget.
            chunk = max(4096, sample_bytes // 3)

            f.seek(0)
            head = shannon_entropy(f.read(chunk))

            mid_offset = max(0, (size // 2) - (chunk // 2))
            f.seek(mid_offset)
            middle = shannon_entropy(f.read(chunk))

            tail_offset = max(0, size - chunk)
            f.seek(tail_offset)
            tail = shannon_entropy(f.read(chunk))

            return max(head, middle, tail)
    except (OSError, PermissionError):
        return None


# ---------------------------------------------------------------------------
# Cryptographic Spike Detector  ("the crypto map")
# ---------------------------------------------------------------------------

class CryptographicSpikeDetector:
    """Fires a `crypto_spike` event when the recent high-entropy write rate
    deviates sharply (sigma-based) from this host's own baseline."""

    def __init__(self, tunnel: "TelemetryTunnel", target_dir: Optional[str] = None):
        self.tunnel = tunnel
        self.target_dir = target_dir
        self._events: deque = deque()
        self._fired_at = 0.0

    def record(self, entropy: float):
        self._events.append((time.time(), entropy))

    def evaluate(self):
        now = time.time()
        while self._events and self._events[0][0] < now - CRYPTO_BASELINE_WINDOW:
            self._events.popleft()
        if len(self._events) < CRYPTO_SPIKE_MIN_FILES:
            return
        recent = [e for e in self._events if e[0] >= now - CRYPTO_SPIKE_WINDOW]
        recent_count = len(recent)
        if recent_count < CRYPTO_SPIKE_MIN_FILES:
            return
        baseline_events = [e for e in self._events if e[0] < now - CRYPTO_SPIKE_WINDOW]
        baseline_span = max(1.0, CRYPTO_BASELINE_WINDOW - CRYPTO_SPIKE_WINDOW)
        n_windows = baseline_span / CRYPTO_SPIKE_WINDOW
        baseline_rate = len(baseline_events) / n_windows
        std = max(1.0, math.sqrt(max(baseline_rate, 1.0)))
        z = (recent_count - baseline_rate) / std
        recent_entropy = sum(e[1] for e in recent) / recent_count
        spike = (z >= CRYPTO_SPIKE_SIGMA) and (recent_entropy >= 7.0)
        if spike and (now - self._fired_at) > CRYPTO_SPIKE_WINDOW:
            self._fired_at = now
            self.tunnel.enqueue(TelemetryEvent(
                vm_id=self.tunnel.vm_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="crypto_spike", severity="critical", score_delta=50,
                details={
                    "reason": "ransomware_crypto_spike",
                    "recent_high_entropy_writes": recent_count,
                    "window_seconds": CRYPTO_SPIKE_WINDOW,
                    "baseline_rate_per_window": round(baseline_rate, 2),
                    "sigma_above_baseline": round(z, 2),
                    "avg_recent_entropy": round(recent_entropy, 3),
                    "message": (f"Cryptographic spike: {recent_count} high-entropy writes "
                                f"in {CRYPTO_SPIKE_WINDOW}s ({z:.1f}sigma above baseline)"),
                    # Review fix: an analyst must be able to see WHO wrote the
                    # files. Attribution is only computed at fire time because
                    # open_files() across all PIDs is expensive.
                    "attributed_writers": attribute_writers(self.target_dir)
                                          if self.target_dir else [],
                }))


# ---------------------------------------------------------------------------
# Filesystem Monitor  (v3 — transition-aware, attribution-aware)
# ---------------------------------------------------------------------------

class _WatchdogFSEventHandler(FileSystemEventHandler):
    """Turns raw filesystem events into (path, kind) tuples on a shared queue.

    Deliberately dumb: no detection logic lives here. All classification
    still happens in FilesystemMonitor, so poll mode and event mode share
    IDENTICAL detection semantics — only how candidate paths are discovered
    differs. That symmetry is what lets the two modes be swapped safely.
    """

    def __init__(self, pending: deque, lock: threading.Lock):
        super().__init__()
        self._pending = pending
        self._lock = lock

    def _push(self, path: str, kind: str) -> None:
        with self._lock:
            self._pending.append((path, kind))

    def on_created(self, event):
        if not event.is_directory:
            self._push(event.src_path, "created")

    def on_modified(self, event):
        if not event.is_directory:
            self._push(event.src_path, "modified")

    def on_deleted(self, event):
        if not event.is_directory:
            self._push(event.src_path, "deleted")

    def on_moved(self, event):
        # Ransomware's write-ciphertext-to-a-new-name-then-delete-original
        # pattern often surfaces as a move; treat it as delete(src) +
        # create(dest) so it goes through the exact same processing path.
        if not event.is_directory:
            self._push(event.src_path, "deleted")
            self._push(event.dest_path, "created")


class FilesystemMonitor:
    """Turns file changes into detection facts, in one of two modes:

    ``mode="event"`` (default, Priority 1.1 fix): filesystem changes are
    discovered via OS-level notifications (inotify / ReadDirectoryChangesW /
    FSEvents, via the `watchdog` library) instead of a fixed-interval walk.
    Detection latency is then bounded by however fast the OS delivers the
    event, not by the poll interval — and anything that starts and finishes
    inside one poll tick, which the old design could miss entirely, is no
    longer invisible.

    ``mode="poll"``: the original `rglob()` walk. Kept as an explicit,
    documented fallback for filesystems where recursive watches are not
    supported (some network mounts, some container overlay filesystems) and
    for any host where `watchdog` is not installed. `mode="event"`
    automatically demotes to `mode="poll"` (logged, never silent) if the
    dependency is missing or the OS watch cannot be established.

    v3 change (external-review fix, unchanged by the above): entropy is no
    longer judged in absolute terms. A backup job rewriting .tar.gz archives
    and ransomware encrypting .docx files BOTH produce ~8.0-bit entropy, so
    the absolute value cannot separate them. We score the plaintext-
    ciphertext TRANSITION via EntropyTransitionTracker instead, which keeps
    the ransomware signal while removing the compressed-workload false
    positive that could trip a +50 instant-block. This logic is shared by
    both modes below (`_process_candidate`), so switching modes cannot
    change what counts as suspicious — only how quickly a change is seen.
    """

    def __init__(self, target_dir, entropy_threshold, velocity_window,
                 velocity_threshold, tunnel, crypto_detector,
                 transitions=None, rename_detector=None,
                 esxi_detector=None, slowburn_detector=None,
                 mode: str = "poll"):
        # NOTE: this class defaults to "poll" so that direct construction
        # without ever calling start() (demo scripts, ad-hoc scan() usage,
        # existing tests) behaves EXACTLY as it did before eventing existed.
        # The live agent (SentryAgent below) explicitly requests mode="auto"
        # and calls start(), which is where eventing actually takes effect.
        self.target_dir = Path(target_dir)
        self.entropy_threshold = entropy_threshold
        self.velocity_window = velocity_window
        self.velocity_threshold = velocity_threshold
        self.tunnel = tunnel
        self.crypto = crypto_detector
        self.transitions = transitions
        self.rename_detector = rename_detector
        self.esxi_detector = esxi_detector
        self.slowburn = slowburn_detector
        self.destruction_detector = None   # set by the agent; wiper detection
        self._seen_mtimes: Dict[str, float] = {}
        self._modification_times: deque = deque()
        self._alerted_files: Set[str] = set()
        self._primed = False

        # "auto" means "prefer eventing, but the constructor/start() fallback
        # below will demote to polling on any failure" — there is no
        # behavioural difference from requesting "event" directly.
        self.mode = "event" if mode == "auto" else mode
        self._pending: deque = deque()
        self._pending_lock = threading.Lock()
        self._observer = None
        if self.mode == "event" and not WATCHDOG_AVAILABLE:
            _agent_log("fs_monitor: watchdog not installed; falling back to poll mode")
            self.mode = "poll"

    # -- eventing lifecycle --------------------------------------------------

    def start(self):
        """Begin OS-level event watching. No-op in poll mode."""
        if self.mode != "event":
            return
        try:
            handler = _WatchdogFSEventHandler(self._pending, self._pending_lock)
            observer = Observer()
            observer.schedule(handler, str(self.target_dir), recursive=True)
            observer.start()
            self._observer = observer
            # No bulk initial inventory happens in event mode (unlike the
            # first poll pass) — every create() seen from here on is
            # genuinely new, so there is no "looks like a mass rename on
            # startup" problem to guard against.
            self._primed = True
        except Exception as exc:
            _agent_log(f"fs_monitor: watchdog observer failed to start "
                       f"({exc.__class__.__name__}: {exc}); falling back to poll mode")
            self.mode = "poll"
            self._observer = None

    def stop(self):
        if self._observer is not None:
            try:
                self._observer.stop()
                self._observer.join(timeout=2.0)
            except Exception:
                pass
            self._observer = None

    # -- shared candidate processing (identical in both modes) --------------

    def _process_candidate(self, path_str: str, is_new: bool, now: float,
                            modified: List[Tuple[str, float, bool, str]]) -> None:
        if is_new and self.rename_detector:
            self.rename_detector.record_new_file(path_str)

        # Analyse NEWLY-CREATED files as well as modified ones.
        #
        # This is not optional. The dominant ransomware pattern is
        # write-ciphertext-to-a-NEW-name then delete the original
        # (report.docx -> report.docx.locked). A monitor that only inspects
        # files whose mtime changed never sees the ciphertext at all, because
        # the encrypted output is a path it has never indexed. Caught by
        # scripts/ransomware_sensor_demo.py.
        ent = file_entropy(path_str)
        if ent is None:
            return
        suspicious, reason = (True, "absolute_threshold")
        if self.transitions:
            suspicious, reason = self.transitions.classify(path_str, ent)
        else:
            suspicious = ent >= self.entropy_threshold
        modified.append((path_str, ent, suspicious, reason))
        self._modification_times.append(now)
        if suspicious:
            self.crypto.record(ent)
            if self.slowburn:
                self.slowburn.record_transition()
        if self.esxi_detector:
            self.esxi_detector.record(path_str, ent, suspicious)

    # -- poll mode ------------------------------------------------------------

    def _scan_poll(self, now: float) -> List[Tuple[str, float, bool, str]]:
        modified: List[Tuple[str, float, bool, str]] = []
        seen_this_pass: Set[str] = set()
        try:
            for entry in self.target_dir.rglob("*"):
                if not entry.is_file():
                    continue
                try:
                    mtime = entry.stat().st_mtime
                except OSError:
                    continue
                path_str = str(entry)
                seen_this_pass.add(path_str)
                prev = self._seen_mtimes.get(path_str)
                self._seen_mtimes[path_str] = mtime

                # NEW file appearing -> feed the extension-rename detector.
                # Skip the very first pass, otherwise the initial inventory of
                # an existing filesystem would look like a mass rename.
                is_new = prev is None and self._primed
                if is_new or (prev is not None and mtime != prev):
                    self._process_candidate(path_str, is_new, now, modified)
        except Exception as exc:
            _agent_log(f"fs_monitor.scan error: {exc.__class__.__name__}: {exc}")

        # Files we knew about that are gone this pass = deletions. Feeds the
        # wiper detector: a destructive attack encrypts nothing, so the entropy
        # sensors stay silent and mass deletion is the only available signal.
        if self._primed and seen_this_pass:
            deleted = [p for p in self._seen_mtimes if p not in seen_this_pass]
            if deleted:
                for p in deleted:
                    self._seen_mtimes.pop(p, None)
                if self.destruction_detector:
                    self.destruction_detector.record_deletions(deleted)

        self._primed = True
        return modified

    # -- event mode -----------------------------------------------------------

    def _drain_pending(self, max_batch: int = 20_000) -> Tuple[List[str], List[str]]:
        """Pull queued (path, kind) tuples off the watchdog callback thread.

        A single scan() call processing an unbounded flood would block the
        whole agent loop, so a very large batch is capped and the remainder
        is left queued for the next tick rather than dropped.
        """
        with self._pending_lock:
            batch = list(self._pending)
            self._pending.clear()
            if len(batch) > max_batch:
                overflow = batch[max_batch:]
                batch = batch[:max_batch]
                self._pending.extendleft(reversed(overflow))

        # Last write wins per path within one drained batch (e.g. a file
        # created then immediately modified before the next scan tick).
        latest_kind: Dict[str, str] = {}
        for path_str, kind in batch:
            latest_kind[path_str] = kind
        created_or_modified = [p for p, k in latest_kind.items() if k != "deleted"]
        deleted = [p for p, k in latest_kind.items() if k == "deleted"]
        return created_or_modified, deleted

    def _scan_event(self, now: float) -> List[Tuple[str, float, bool, str]]:
        modified: List[Tuple[str, float, bool, str]] = []
        created_or_modified, deleted = self._drain_pending()

        for path_str in created_or_modified:
            prev = self._seen_mtimes.get(path_str)
            is_new = prev is None
            try:
                mtime = os.path.getmtime(path_str)
            except OSError:
                # Gone again before we got to it — the write-then-delete
                # race. Nothing left to sample; not an error.
                continue
            self._seen_mtimes[path_str] = mtime
            self._process_candidate(path_str, is_new, now, modified)

        if deleted:
            for p in deleted:
                self._seen_mtimes.pop(p, None)
            if self.destruction_detector:
                self.destruction_detector.record_deletions(deleted)

        self._primed = True
        return modified

    def scan(self):
        now = time.time()
        if self.mode == "event":
            modified = self._scan_event(now)
        else:
            modified = self._scan_poll(now)

        cutoff = now - self.velocity_window
        while self._modification_times and self._modification_times[0] < cutoff:
            self._modification_times.popleft()
        velocity = len(self._modification_times)
        velocity_spike = velocity >= self.velocity_threshold

        for path_str, ent, suspicious, reason in modified:
            if suspicious and ent >= self.entropy_threshold and path_str not in self._alerted_files:
                self._alerted_files.add(path_str)
                self.tunnel.enqueue(TelemetryEvent(
                    vm_id=self.tunnel.vm_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    event_type="entropy", severity="critical", score_delta=40,
                    details={"path": path_str, "entropy": round(ent, 4),
                             "threshold": self.entropy_threshold,
                             "classification": reason,
                             "velocity": velocity, "velocity_spike": velocity_spike}))

        if velocity_spike and modified:
            # distinct 'velocity' type so the controller scores it as +20, not +40
            self.tunnel.enqueue(TelemetryEvent(
                vm_id=self.tunnel.vm_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="velocity", severity="high", score_delta=20,
                details={"message": f"Modification velocity spike: {velocity} files in {self.velocity_window}s",
                         "velocity": velocity}))

        self.crypto.evaluate()
        if self.rename_detector:
            self.rename_detector.evaluate()
        if self.esxi_detector:
            self.esxi_detector.evaluate()
        if self.slowburn:
            self.slowburn.evaluate()
        if self.destruction_detector:
            self.destruction_detector.evaluate()
        return modified


# ---------------------------------------------------------------------------
# Process Lineage Monitor
# ---------------------------------------------------------------------------

class ProcessLineageMonitor:
    def __init__(self, tunnel):
        self.tunnel = tunnel
        self._alerted_pids: Set[int] = set()
        self._is_windows = platform.system() == "Windows"

    def scan(self):
        suspicious_paths = SUSPICIOUS_PATHS_WIN if self._is_windows else SUSPICIOUS_PATHS_LINUX
        try:
            procs = {p.pid: p for p in psutil.process_iter(
                ["pid", "name", "exe", "ppid", "cmdline", "username"])}
        except Exception:
            return
        pid_to_name = {pid: (p.info.get("name") or "").lower() for pid, p in procs.items()}

        for pid, proc in procs.items():
            if pid in self._alerted_pids:
                continue
            try:
                info = proc.info
                name = (info.get("name") or "").lower()
                exe = (info.get("exe") or "").lower()
                ppid = info.get("ppid") or 0
                cmdline = " ".join(info.get("cmdline") or []).lower()

                for sus in suspicious_paths:
                    if sus in exe:
                        self._alerted_pids.add(pid)
                        self.tunnel.enqueue(TelemetryEvent(
                            vm_id=self.tunnel.vm_id,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            event_type="process", severity="high", score_delta=40,
                            details={"reason": "suspicious_exec_path", "pid": pid,
                                     "name": name, "exe": exe, "sus_path": sus}))
                        break

                parent_name = pid_to_name.get(ppid, "")
                if name in SUSPICIOUS_LINEAGE.get(parent_name, set()) and pid not in self._alerted_pids:
                    self._alerted_pids.add(pid)
                    self.tunnel.enqueue(TelemetryEvent(
                        vm_id=self.tunnel.vm_id,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        event_type="process", severity="critical", score_delta=30,
                        details={"reason": "web_server_spawned_shell",
                                 "parent_name": parent_name, "parent_pid": ppid,
                                 "child_name": name, "child_pid": pid, "exe": exe}))

                backup_kill = SHADOW_COMMANDS if self._is_windows else UNIX_BACKUP_DESTRUCTION
                for cmd in backup_kill:
                    if cmd in cmdline and pid not in self._alerted_pids:
                        self._alerted_pids.add(pid)
                        self.tunnel.enqueue(TelemetryEvent(
                            vm_id=self.tunnel.vm_id,
                            timestamp=datetime.now(timezone.utc).isoformat(),
                            event_type="shadow", severity="critical", score_delta=40,
                            details={"reason": "backup_destruction_detected",
                                     "command": cmdline[:256], "pid": pid, "name": name}))
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue


# ---------------------------------------------------------------------------
# Socket / Network Monitor
# ---------------------------------------------------------------------------

class SocketMonitor:
    def __init__(self, tunnel):
        self.tunnel = tunnel
        self._alerted_conns: Set[Tuple] = set()

    def scan(self):
        try:
            connections = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError):
            return
        benign_system = {"svchost", "system", "systemd", "networkmanager", "dhclient",
                         "ntpd", "chronyd", "resolvd", "apt", "dpkg", "yum", "dnf", "pip"}
        for conn in connections:
            if conn.status != "ESTABLISHED" or conn.raddr is None or conn.pid is None:
                continue
            key = (conn.pid, conn.raddr.ip, conn.raddr.port)
            if key in self._alerted_conns:
                continue
            try:
                proc = psutil.Process(conn.pid)
                proc_name = (proc.name() or "").lower()
                exe = (proc.exe() or "").lower()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if any(b in proc_name for b in KNOWN_BROWSER_NAMES):
                continue
            if any(b in proc_name for b in benign_system):
                continue
            dest_ip, dest_port = conn.raddr.ip, conn.raddr.port
            # Same B108 false positive as SUSPICIOUS_PATHS_LINUX above — a
            # detection signature, not a write target. nosec must be on the
            # line bandit actually anchors the finding to (the string
            # literals below), not the line the expression starts on —
            # confirmed by re-running bandit after an earlier placement
            # that looked right but didn't actually suppress anything.
            is_suspicious = (dest_port not in {80, 443, 53, 123}
                             or any(s in exe for s in ["/tmp/", "/var/tmp/", "/dev/shm/"]))  # nosec B108
            if is_suspicious:
                self._alerted_conns.add(key)
                self.tunnel.enqueue(TelemetryEvent(
                    vm_id=self.tunnel.vm_id,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    event_type="network", severity="medium", score_delta=15,
                    details={"reason": "unexpected_outbound_connection",
                             "proc_name": proc_name, "exe": exe, "pid": conn.pid,
                             "dest_ip": dest_ip, "dest_port": dest_port,
                             "laddr_port": conn.laddr.port if conn.laddr else None}))


# ---------------------------------------------------------------------------
# Heartbeat (self-attestation)
# ---------------------------------------------------------------------------

class HeartbeatEmitter:
    def __init__(self, tunnel, interval: float = 15.0):
        self.tunnel = tunnel
        self.interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="Heartbeat")
        self._seq = 0

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _loop(self):
        while not self._stop.is_set():
            self._seq += 1
            self.tunnel.enqueue(TelemetryEvent(
                vm_id=self.tunnel.vm_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type="heartbeat", severity="low", score_delta=0,
                details={"cpu_percent": psutil.cpu_percent(interval=None),
                         "mem_percent": psutil.virtual_memory().percent,
                         "uptime_s": int(time.time() - psutil.boot_time()),
                         "agent_seq": self._seq, "interval_s": self.interval}))
            self._stop.wait(self.interval)


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

class SentryAgent:
    def __init__(self, config: argparse.Namespace):
        self.config = config
        vm_id = config.vm_id or socket.gethostname()
        master = load_master_secret(fallback_file=config.key_file)
        sender = SecureSender(master, vm_id, prefer_aesgcm=not config.force_hmac)
        self.tunnel = TelemetryTunnel(config.controller_host, config.controller_port, sender, vm_id)

        # Persistent baseline: learned state now survives restarts instead of
        # cold-starting after every maintenance window (external-review gap).
        self.store = BaselineStore(config.baseline_state)

        def _emit(event_type: str, severity: str, details: dict):
            """Sensor callback. Sensors report facts; the controller scores."""
            self.tunnel.enqueue(TelemetryEvent(
                vm_id=vm_id,
                timestamp=datetime.now(timezone.utc).isoformat(),
                event_type=event_type, severity=severity, score_delta=0,
                details=details))

        self.transitions = EntropyTransitionTracker(self.store)
        self.crypto = CryptographicSpikeDetector(self.tunnel, target_dir=config.target_dir)
        self.rename_detector = ExtensionRenameDetector(_emit)
        self.esxi_detector = EsxiEncryptionDetector(_emit)
        self.slowburn = SlowBurnDetector(_emit, store=self.store)
        self.egress = EgressVolumeMonitor(
            _emit, bytes_threshold=int(config.egress_threshold_mb) * 1024 * 1024,
            store=self.store)

        self.fs_monitor = FilesystemMonitor(
            config.target_dir, config.entropy_threshold, DEFAULT_ENTROPY_WINDOW,
            DEFAULT_VELOCITY_THRESHOLD, self.tunnel, self.crypto,
            transitions=self.transitions, rename_detector=self.rename_detector,
            esxi_detector=self.esxi_detector, slowburn_detector=self.slowburn,
            mode=getattr(config, "fs_mode", "auto"))
        # Modern threat suite: cloud/identity/container/supply-chain/C2/impact.
        # These sweep open files and sockets across every PID, so they are far
        # heavier than the filesystem walk and run on their own slower cadence.
        self.modern = ModernThreatSuite(
            _emit, enable_reverse_shell=not config.disable_reverse_shell)
        self.fs_monitor.destruction_detector = self.modern.destruction
        self._last_modern_scan = 0.0

        self.proc_monitor = ProcessLineageMonitor(self.tunnel)
        self.sock_monitor = SocketMonitor(self.tunnel)
        self.heartbeat = HeartbeatEmitter(self.tunnel, interval=config.heartbeat_interval)
        self._last_persist = 0.0

    def _persist_state(self, force: bool = False):
        now = time.time()
        if not force and (now - self._last_persist) < 60.0:
            return
        self._last_persist = now
        try:
            self.transitions.persist()
            self.slowburn.persist()
            self.egress.persist()
            self.store.save()
        except Exception as exc:
            _agent_log(f"state persist failed: {exc.__class__.__name__}: {exc}")

    def run(self):
        backend = "HMAC-AEAD" if self.config.force_hmac else "AES-256-GCM (fallback HMAC-AEAD)"
        print(f"[*] Exonerve Sentry Agent v3 starting. VM: {self.tunnel.vm_id}")
        print(f"[*] Controller: {self.config.controller_host}:{self.config.controller_port}")
        print(f"[*] Target dir: {self.config.target_dir}")
        print(f"[*] Secure channel: {backend}")
        print("[*] Ransomware sensors: entropy-transition, crypto-spike, "
              "ext-rename, esxi, slow-burn, egress-volume")
        print("[*] Modern sensors: imds, credential-files, browser-stealer, "
              "container-escape, k8s-token, supply-chain, web-c2, tunnel, "
              "cryptominer, wiper, log-tamper, reverse-shell, ssh-persistence")
        print(f"[*] Modern scan interval: {self.config.modern_scan_interval}s")
        print(f"[*] Baseline state: {self.store.path}")
        print(f"[*] Filesystem monitoring mode: {self.fs_monitor.mode}"
              + ("" if self.fs_monitor.mode == "poll" else
                 " (falls back to poll automatically if unavailable)"))
        self.tunnel.start()
        self.heartbeat.start()
        self.fs_monitor.start()
        try:
            while True:
                try:
                    self.fs_monitor.scan()
                    self.proc_monitor.scan()
                    self.sock_monitor.scan()
                    self.egress.sample()
                    self.egress.evaluate()
                    now_t = time.time()
                    if now_t - self._last_modern_scan >= self.config.modern_scan_interval:
                        self._last_modern_scan = now_t
                        self.modern.scan_all()
                    self._persist_state()
                except Exception as exc:
                    _agent_log(f"monitor loop error: {exc.__class__.__name__}: {exc}")
                time.sleep(self.config.poll_interval)
        except KeyboardInterrupt:
            print("\n[*] Agent shutting down.")
        finally:
            self._persist_state(force=True)
            self.tunnel.stop()
            self.heartbeat.stop()
            self.fs_monitor.stop()


def main():
    parser = argparse.ArgumentParser(description="Exonerve Sentry Agent v2")
    parser.add_argument("--controller-host", default=DEFAULT_CONTROLLER_HOST)
    parser.add_argument("--controller-port", type=int, default=DEFAULT_CONTROLLER_PORT)
    parser.add_argument("--target-dir", default=DEFAULT_TARGET_DIR)
    parser.add_argument("--entropy-threshold", type=float, default=DEFAULT_ENTROPY_THRESHOLD)
    parser.add_argument("--poll-interval", type=float, default=DEFAULT_POLL_INTERVAL)
    parser.add_argument("--heartbeat-interval", type=float, default=15.0)
    parser.add_argument("--vm-id", default=None)
    parser.add_argument("--key-file", default=None)
    parser.add_argument("--force-hmac", action="store_true")
    parser.add_argument("--baseline-state", default=None,
                        help="Path to persistent baseline state file")
    parser.add_argument("--egress-threshold-mb", type=int, default=500,
                        help="Outbound MB in a 5min window that flags bulk exfil")
    parser.add_argument("--modern-scan-interval", type=float, default=15.0,
                        help="Seconds between modern-threat sweeps (heavier than FS walk)")
    parser.add_argument("--disable-reverse-shell", action="store_true",
                        help="Disable /proc-based reverse-shell detection (Linux-only sensor)")
    parser.add_argument("--fs-mode", choices=("auto", "event", "poll"), default="auto",
                        help="Filesystem monitoring mode. 'auto'/'event' use OS-level "
                             "notifications (inotify/ReadDirectoryChangesW/FSEvents) via "
                             "watchdog, and fall back to polling automatically if that "
                             "isn't available. 'poll' forces the interval-based walk — use "
                             "this on filesystems that don't support recursive watches "
                             "(some network mounts, some container overlay filesystems).")
    args = parser.parse_args()
    SentryAgent(args).run()


if __name__ == "__main__":
    main()
