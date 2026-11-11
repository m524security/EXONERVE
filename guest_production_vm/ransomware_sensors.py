#!/usr/bin/env python3
"""
Exonerve :: Ransomware Sensor Pack  (v3.8)
==============================================
Closes the ransomware gaps identified in external review of v3.7.1:

  1. cloud_exfil (T1567.002) had NO live emitter — only the replay harness
     injected it. Double-extortion steals data BEFORE encrypting; without an
     egress sensor the theft is invisible. -> EgressVolumeMonitor.
  2. ransomware_esxi (T1486) had NO live emitter.  -> EsxiEncryptionDetector.
  3. Mass extension rename (.locked/.wncry) was not watched at all, despite
     being the fastest and lowest-FP ransomware signal. -> ExtensionRenameDetector.
  4. crypto_spike counted ABSOLUTE entropy, so legitimately-compressed writes
     (.gz/.zip/.mp4 all sit at ~7.9-8.0 bits/byte) looked identical to
     ciphertext -> a nightly backup could trip a +50 instant-block.
     -> EntropyTransitionTracker scores the low->high TRANSITION instead.
  5. Throttled ransomware never trips a 3-sigma burst test.
     -> SlowBurnDetector (long-window cumulative, sigma-independent).
  6. Baseline lived in RAM and reset on every restart. -> BaselineStore.

Design rule kept from the original codebase: sensors emit FACTS with a
suggested severity. They never decide a verdict — the Host Control Plane
scores authoritatively. Agent-supplied score_delta remains untrusted.

HONEST LIMITATION (documented, not hidden):
  Per-process network byte accounting is not portable through psutil. The
  kernel exposes byte counters per-interface, not per-PID, on the platforms we
  target. EgressVolumeMonitor therefore correlates a *system-wide* egress
  surge with the set of non-allowlisted processes holding established outbound
  sockets during that window. Attribution is CORRELATIONAL, not kernel-exact:
  the byte volume is measured truth, the named process is the leading
  candidate. This is stated in the emitted event as `attribution: correlational`
  so an analyst is never misled.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import psutil
except Exception:  # pragma: no cover - psutil is a hard dep of the agent
    psutil = None


# ---------------------------------------------------------------------------
# Tunables
# ---------------------------------------------------------------------------

# Entropy bands. Ciphertext and compressed data both sit near 8.0, so absolute
# entropy alone cannot separate them. The TRANSITION is what discriminates.
ENTROPY_CIPHERTEXT = 7.2      # at/above this a file looks encrypted-or-compressed
ENTROPY_PLAINTEXT = 6.5       # below this a file looked like ordinary content

# Extensions whose contents are ALREADY high-entropy when perfectly healthy.
# Used ONLY for first-sight files where no prior entropy is known. Once we have
# a prior reading we use the transition instead, so encrypting a .docx in place
# is still caught (no blind spot introduced by this list).
NATIVELY_HIGH_ENTROPY_EXT: Set[str] = {
    ".gz", ".bz2", ".xz", ".zst", ".lz4", ".zip", ".7z", ".rar", ".tar", ".tgz",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".heic", ".tiff",
    ".mp4", ".mkv", ".avi", ".mov", ".webm", ".mp3", ".flac", ".ogg", ".opus",
    ".pdf", ".docx", ".xlsx", ".pptx", ".odt", ".ods", ".epub",
    ".iso", ".img", ".deb", ".rpm", ".whl", ".jar", ".apk", ".dmg",
    ".woff", ".woff2", ".pyc", ".so", ".dll", ".exe", ".bin",
    ".gpg", ".pgp", ".asc", ".age", ".kdbx",
}

# Extensions that are unremarkable on a normal filesystem. A burst of NEW files
# sharing an extension outside this set is the classic ".locked" tell.
COMMON_EXT: Set[str] = NATIVELY_HIGH_ENTROPY_EXT | {
    ".txt", ".md", ".rst", ".log", ".csv", ".tsv", ".json", ".yaml", ".yml",
    ".xml", ".html", ".htm", ".css", ".js", ".ts", ".py", ".c", ".h", ".cpp", ".cc",
    ".go", ".rs", ".java", ".rb", ".php", ".sh", ".bat", ".ps1", ".sql",
    ".conf", ".cfg", ".ini", ".toml", ".env", ".lock", ".doc", ".xls", ".ppt",
    ".swp", ".tmp", ".bak", ".part", ".crdownload", ".db", ".sqlite", ".dat",
    "",  # extensionless files are extremely common
} | {
    # Compiler / build-toolchain OUTPUT extensions. Found missing via the
    # v3.10 false-positive corpus (tests/corpus/, Priority 1.3): a
    # multi-language CI build clustering 90+ new .o/.d files inside one
    # RENAME_WINDOW would have tripped the extension-clustering check below
    # — a real gap, not a hypothetical one, first observed when the corpus
    # scenario for "CI build server" produced an unexpected ext_rename fire.
    # ACCEPTED TRADEOFF, documented in DEFENSE_GUIDE.md: ransomware that
    # specifically renames its encrypted output to one of these extensions
    # would now evade the clustering AND novel-rate checks the same way it
    # already could with any other COMMON_EXT entry. This is the existing
    # design tradeoff of an allowlist-based approach, not a new one.
    ".o", ".obj", ".d", ".a", ".lib", ".exp", ".ilk", ".pdb",
    ".rlib", ".rmeta", ".class", ".wasm", ".map",
}

# Virtual-machine disk artifacts. Mass encryption of these from a hypervisor
# takes down many VMs at once — the modern high-leverage ransomware move.
VM_DISK_EXT: Set[str] = {
    ".vmdk", ".vmx", ".vswp", ".nvram", ".vmsd", ".vmsn", ".vmem",
    ".qcow2", ".qcow", ".vhd", ".vhdx", ".vdi", ".raw",
}

# Extension-rename detector
RENAME_WINDOW = 60            # seconds
RENAME_MIN_FILES = 12         # new files sharing one unusual extension

# Novel-extension-rate signal (v3.10, Priority 2.1) — closes the randomised-
# per-file-extension bypass: ransomware that gives every victim file its own
# unique suffix never clusters on one extension, so RENAME_MIN_FILES above
# never trips. A burst of never-before-seen extensions is anomalous on its
# own, whether or not any of them repeat.
NOVEL_EXT_WINDOW = 60          # seconds
NOVEL_EXT_MIN_DISTINCT = 15    # distinct brand-new extensions within the window
# Found via the v3.10 FP corpus (tests/corpus/): a large multi-language build
# server can legitimately produce 15+ distinct output extensions (.o, .obj,
# .rlib, .class, .wasm...) the first time it runs. What separates that from
# ransomware giving every victim file its own random extension isn't the
# absolute count, it's the RATIO: a build's novel extensions are a small
# fraction of that window's new files (a handful of types across thousands
# of files), while per-file-random-extension ransomware is close to 1
# novel extension per novel file. Require both.
NOVEL_EXT_MIN_RATIO = 0.5      # novel extensions ÷ all new files in the window

# Medium-cardinality extension-pool evasion (v3.13 fix — this was tracked
# as PLANNED/open since v3.10, now implemented). An attacker can tune a
# pool of roughly 8-14 random extensions, each used just under
# RENAME_MIN_FILES times, to stay under BOTH the clustering check
# (per-extension count) and the fast novel-rate check (distinct-count in
# 60s) AT THE SAME TIME — neither fast threshold has a form this can't be
# dodged by staying one below it. A LONGER window closes it differently:
# a normal host mints new file extensions rarely (a tool installed here and
# there); introducing a dozen-plus BRAND NEW extensions inside even a full
# day is anomalous on a timescale an attacker can no longer tune around
# without slowing the attack from minutes to days — a real, meaningful cost
# given ransomware's whole point is speed before it's noticed.
LONG_WINDOW_NOVEL_EXT_SECONDS = 86400      # 24 hours
LONG_WINDOW_NOVEL_EXT_MIN_DISTINCT = 20    # generously calibrated: even a busy
                                             # multi-language dev host rarely
                                             # introduces 20 NEW extensions in
                                             # one day once its toolchain is set

# ESXi detector
ESXI_WINDOW = 60
ESXI_MIN_FILES = 3            # VM disks are huge; even a few is catastrophic

# Slow-burn detector — catches throttled encryption that never spikes
SLOWBURN_WINDOW = 3600        # 1 hour
SLOWBURN_MIN_TRANSITIONS = 150

# Egress / exfil detector
EGRESS_WINDOW = 300           # 5 minutes
EGRESS_BYTES_THRESHOLD = 500 * 1024 * 1024   # 500 MB outbound in the window
EGRESS_SUSTAINED_SAMPLES = 3  # must be sustained, not one burst sample

# Processes whose outbound traffic is expected and not exfil-suspicious.
EGRESS_ALLOWLIST: Set[str] = {
    "chrome", "chromium", "firefox", "brave", "edge", "msedge", "opera",
    "safari", "vivaldi", "systemd", "systemd-resolved", "networkmanager",
    "dhclient", "ntpd", "chronyd", "apt", "apt-get", "dpkg", "yum", "dnf",
    "snapd", "packagekitd", "docker", "dockerd", "containerd", "kubelet",
    "rsync", "sshd", "postfix", "nginx", "apache2", "httpd",
}

# Known bulk-transfer / cloud-storage client names. Presence RAISES confidence
# but is NEVER required — the volume is the signal, so renaming the binary
# does not evade the detector (that was the review's specific objection).
BULK_TRANSFER_HINTS: Set[str] = {
    "rclone", "megacmd", "megasync", "mega-cmd", "aws", "s3cmd", "s5cmd",
    "gsutil", "azcopy", "dropbox", "onedrive", "gdrive", "curl", "wget",
    "filezilla", "winscp", "ftp", "sftp", "croc", "magic-wormhole",
}


# ---------------------------------------------------------------------------
# Persistent baseline store  (review gap: baselines reset on every restart)
# ---------------------------------------------------------------------------

class BaselineStore:
    """Small atomic JSON store so learned baselines survive agent restarts.

    Deliberately dependency-free and best-effort: a corrupt or unreadable state
    file must degrade to 'cold start', never crash the agent.
    """

    def __init__(self, path: Optional[str] = None):
        self.path = path or os.environ.get(
            "EXONERVE_BASELINE_STATE",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentry_baseline.json"),
        )
        self._data: Dict = {}
        self.load()

    def load(self) -> Dict:
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                loaded = json.load(fh)
            self._data = loaded if isinstance(loaded, dict) else {}
        except Exception:
            self._data = {}
        return self._data

    def get(self, key: str, default=None):
        return self._data.get(key, default)

    def set(self, key: str, value) -> None:
        self._data[key] = value

    def save(self) -> bool:
        """Atomic write (tmp + replace) so a kill mid-write cannot corrupt state."""
        try:
            directory = os.path.dirname(self.path) or "."
            os.makedirs(directory, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=".baseline-", suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fh:
                    json.dump(self._data, fh)
                os.replace(tmp, self.path)
            finally:
                if os.path.exists(tmp):
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
            return True
        except Exception:
            return False


# ---------------------------------------------------------------------------
# Entropy transition tracking  (review gap: compressed-file false positives)
# ---------------------------------------------------------------------------

class EntropyTransitionTracker:
    """Discriminates ciphertext from legitimately-compressed data.

    A .tar.gz rewritten by a backup job goes high-entropy -> high-entropy.
    A .docx encrypted by ransomware goes low-entropy -> high-entropy.
    Absolute entropy cannot tell these apart; the transition can.
    """

    def __init__(self, store: Optional[BaselineStore] = None, max_tracked: int = 200_000):
        self._prior: Dict[str, float] = {}
        self._max_tracked = max_tracked
        self._store = store
        if store:
            prior = store.get("file_entropy_priors", {})
            if isinstance(prior, dict):
                self._prior = {k: float(v) for k, v in prior.items()
                               if isinstance(v, (int, float))}

    @staticmethod
    def _ext(path: str) -> str:
        return os.path.splitext(path)[1].lower()

    def classify(self, path: str, entropy: float) -> Tuple[bool, str]:
        """Return (is_encryption_suspicious, reason).

        first_sight_* reasons carry lower confidence than an observed
        transition, and the caller weights them accordingly.
        """
        prior = self._prior.get(path)
        self._remember(path, entropy)

        if entropy < ENTROPY_CIPHERTEXT:
            return False, "below_ciphertext_band"

        if prior is None:
            # No history for this file. Fall back to the extension heuristic —
            # only for files whose healthy state is genuinely high entropy.
            if self._ext(path) in NATIVELY_HIGH_ENTROPY_EXT:
                return False, "first_sight_natively_high_entropy"
            return True, "first_sight_unexpected_high_entropy"

        if prior >= ENTROPY_CIPHERTEXT:
            # Already looked encrypted/compressed before this write. A backup
            # job rewriting archives lands here and is correctly ignored.
            return False, "already_high_entropy_before_write"

        if prior <= ENTROPY_PLAINTEXT:
            return True, "plaintext_to_ciphertext_transition"

        return True, "midband_to_ciphertext_transition"

    def _remember(self, path: str, entropy: float) -> None:
        if len(self._prior) >= self._max_tracked:
            # Cheap bounded eviction — drop an arbitrary slice rather than grow
            # without limit on a huge filesystem.
            for k in list(self._prior.keys())[: self._max_tracked // 10]:
                self._prior.pop(k, None)
        self._prior[path] = entropy

    def persist(self) -> None:
        if not self._store:
            return
        # Persist a bounded sample; the point is warm-start, not a full index.
        sample = dict(list(self._prior.items())[:20_000])
        self._store.set("file_entropy_priors", sample)


# ---------------------------------------------------------------------------
# Process attribution  (review gap: "who is writing these files?")
# ---------------------------------------------------------------------------

def attribute_writers(target_dir: str, limit: int = 5) -> List[Dict]:
    """Best-effort: which non-system processes currently hold files open under
    target_dir. Run ONLY when a detector is about to fire (open_files() across
    every PID is expensive), so it costs nothing on the happy path.
    """
    if psutil is None:
        return []
    target = str(Path(target_dir).resolve())
    found: List[Dict] = []
    try:
        for proc in psutil.process_iter(["pid", "name", "exe", "username"]):
            if len(found) >= limit:
                break
            try:
                name = (proc.info.get("name") or "").lower()
                if name in EGRESS_ALLOWLIST:
                    continue
                open_paths = [f.path for f in proc.open_files()
                              if str(Path(f.path).resolve()).startswith(target)]
                if open_paths:
                    found.append({
                        "pid": proc.info.get("pid"),
                        "name": name,
                        "exe": (proc.info.get("exe") or "")[:256],
                        "user": proc.info.get("username"),
                        "open_under_target": len(open_paths),
                        "sample_paths": open_paths[:3],
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue
    except Exception:
        return found
    return found


# ---------------------------------------------------------------------------
# Extension-rename detector  (review gap: fastest ransomware signal missing)
# ---------------------------------------------------------------------------

class ExtensionRenameDetector:
    """Fires when many NEW files suddenly share one unusual extension, OR
    when never-before-seen extensions appear at an anomalous rate.

    Pairing old->new names is unreliable (ransomware often deletes+creates),
    so the primary check detects the population signature instead: nothing
    legitimate creates 12 new '.locked' files in 60 seconds.

    v3.10 (Priority 2.1) adds a second, independent signal in the same
    detector: some ransomware families give every victim file a UNIQUE random
    extension per file specifically so no single extension ever clusters
    above RENAME_MIN_FILES. That population never trips the check above, no
    matter how large min_files or how small window is set — clustering on
    "one extension" is the wrong invariant for that family. What is invariant
    either way is that a normal filesystem does not mint a dozen-plus
    genuinely new extensions in a minute; a healthy host's extension
    vocabulary is small and stable. `_evaluate_novel_rate` tracks the RATE of
    first-time-seen extensions, independent of whether any of them repeat.
    """

    def __init__(self, emit, window: int = RENAME_WINDOW, min_files: int = RENAME_MIN_FILES,
                 novel_window: int = NOVEL_EXT_WINDOW,
                 novel_min_distinct: int = NOVEL_EXT_MIN_DISTINCT,
                 novel_min_ratio: float = NOVEL_EXT_MIN_RATIO,
                 long_window: int = LONG_WINDOW_NOVEL_EXT_SECONDS,
                 long_window_min_distinct: int = LONG_WINDOW_NOVEL_EXT_MIN_DISTINCT):
        self._emit = emit
        self.window = window
        self.min_files = min_files
        self._recent: deque = deque()          # (ts, ext, path)
        self._fired_ext: Dict[str, float] = {}

        # Novel-extension-rate state (Priority 2.1).
        self.novel_window = novel_window
        self.novel_min_distinct = novel_min_distinct
        self.novel_min_ratio = novel_min_ratio
        self._known_exts: Set[str] = set()
        self._novel_recent: deque = deque()    # (ts, ext, path) — first-sight only
        self._novel_fired_at = 0.0

        # Long-window novelty state (v3.13) — same "first sight" signal as
        # above, fed into a SECOND, much longer-lived deque rather than a
        # separate implementation, since "is this extension novel" is one
        # question asked at two different timescales, not two questions.
        self.long_window = long_window
        self.long_window_min_distinct = long_window_min_distinct
        self._long_window_novel: deque = deque()   # (ts, ext, path)
        self._long_window_fired_at = 0.0

    def record_new_file(self, path: str) -> None:
        ext = os.path.splitext(path)[1].lower()
        if ext in COMMON_EXT:
            return
        if len(ext) > 12 or not ext.startswith("."):
            return
        now = time.time()
        self._recent.append((now, ext, path))
        if ext not in self._known_exts:
            self._known_exts.add(ext)
            self._novel_recent.append((now, ext, path))
            self._long_window_novel.append((now, ext, path))

    def evaluate(self) -> Optional[Dict]:
        now = time.time()
        while self._recent and self._recent[0][0] < now - self.window:
            self._recent.popleft()

        cluster_finding: Optional[Dict] = None
        if self._recent:
            by_ext: Dict[str, List[str]] = defaultdict(list)
            for _, ext, path in self._recent:
                by_ext[ext].append(path)

            for ext, paths in by_ext.items():
                if len(paths) < self.min_files:
                    continue
                if now - self._fired_ext.get(ext, 0.0) < self.window:
                    continue
                self._fired_ext[ext] = now
                detail = {
                    "reason": "mass_extension_rename",
                    "extension": ext,
                    "file_count": len(paths),
                    "window_seconds": self.window,
                    "sample_paths": paths[:5],
                    "message": (f"{len(paths)} new '{ext}' files in {self.window}s — "
                                f"consistent with ransomware renaming encrypted output"),
                }
                self._emit("ext_rename", "critical", detail)
                cluster_finding = detail
                break

        # Independent of the clustering result above: check the rate of
        # never-before-seen extensions regardless of whether _recent expired.
        novel_finding = self._evaluate_novel_rate(now)
        long_window_finding = self._evaluate_long_window_novelty(now)
        return cluster_finding or novel_finding or long_window_finding

    def _evaluate_novel_rate(self, now: float) -> Optional[Dict]:
        while self._novel_recent and self._novel_recent[0][0] < now - self.novel_window:
            self._novel_recent.popleft()
        if len(self._novel_recent) < self.novel_min_distinct:
            return None

        # Ratio gate — see NOVEL_EXT_MIN_RATIO for why this exists. Denominator
        # is ALL new non-common-extension files in the same window (self._recent
        # already tracks exactly that population), not just the novel subset.
        total_in_window = sum(1 for ts, _, _ in self._recent if ts >= now - self.novel_window)
        if total_in_window > 0:
            ratio = len(self._novel_recent) / total_in_window
            if ratio < self.novel_min_ratio:
                return None

        if now - self._novel_fired_at < self.novel_window:
            return None
        self._novel_fired_at = now
        exts = [e for _, e, _ in self._novel_recent]
        paths = [p for _, _, p in self._novel_recent]
        detail = {
            "reason": "novel_extension_rate_spike",
            "distinct_new_extensions": len(exts),
            "window_seconds": self.novel_window,
            "novelty_ratio": round(len(self._novel_recent) / max(1, total_in_window), 3),
            "sample_extensions": exts[:10],
            "sample_paths": paths[:5],
            "message": (f"{len(exts)} never-before-seen file extensions appeared "
                        f"in {self.novel_window}s — consistent with ransomware "
                        f"giving each victim file a distinct random extension to "
                        f"evade single-extension clustering detection"),
        }
        self._emit("ext_rate_spike", "critical", detail)
        return detail

    def _evaluate_long_window_novelty(self, now: float) -> Optional[Dict]:
        while self._long_window_novel and self._long_window_novel[0][0] < now - self.long_window:
            self._long_window_novel.popleft()
        if len(self._long_window_novel) < self.long_window_min_distinct:
            return None
        # No ratio gate here, deliberately: over a 24h window a legitimate
        # host's genuinely-NEW extension count converges to a small number
        # regardless of total file volume (yesterday's build tools are
        # today's already-known ones) — the count alone is already the
        # right-shaped signal at this timescale, unlike at the 60s scale
        # where a single build burst can look identical to an attack burst.
        if now - self._long_window_fired_at < self.long_window:
            return None
        self._long_window_fired_at = now
        exts = [e for _, e, _ in self._long_window_novel]
        paths = [p for _, _, p in self._long_window_novel]
        detail = {
            "reason": "long_window_novel_extension_accumulation",
            "distinct_new_extensions": len(exts),
            "window_seconds": self.long_window,
            "sample_extensions": exts[:15],
            "sample_paths": paths[:5],
            "message": (f"{len(exts)} never-before-seen file extensions "
                       f"accumulated over {self.long_window / 3600:.0f}h — "
                       f"catches an attacker deliberately tuning a medium-"
                       f"sized extension pool to stay under the fast-window "
                       f"clustering and novel-rate thresholds simultaneously"),
        }
        self._emit("ext_rate_spike", "high", detail)
        return detail


# ---------------------------------------------------------------------------
# ESXi / hypervisor datastore encryption detector
# ---------------------------------------------------------------------------

class EsxiEncryptionDetector:
    def __init__(self, emit, window: int = ESXI_WINDOW, min_files: int = ESXI_MIN_FILES):
        self._emit = emit
        self.window = window
        self.min_files = min_files
        self._hits: deque = deque()
        self._fired_at = 0.0

    def record(self, path: str, entropy: float, suspicious_transition: bool) -> None:
        if os.path.splitext(path)[1].lower() not in VM_DISK_EXT:
            return
        if entropy < ENTROPY_CIPHERTEXT or not suspicious_transition:
            return
        self._hits.append((time.time(), path, entropy))

    def evaluate(self) -> Optional[Dict]:
        now = time.time()
        while self._hits and self._hits[0][0] < now - self.window:
            self._hits.popleft()
        if len(self._hits) < self.min_files:
            return None
        if now - self._fired_at < self.window:
            return None
        self._fired_at = now
        paths = [h[1] for h in self._hits]
        detail = {
            "reason": "vmdk_mass_encrypt",
            "vm_artifact_count": len(paths),
            "window_seconds": self.window,
            "sample_paths": paths[:5],
            "avg_entropy": round(sum(h[2] for h in self._hits) / len(self._hits), 3),
            "message": (f"{len(paths)} virtual-machine disk artifacts encrypted in "
                        f"{self.window}s — hypervisor datastore ransomware"),
        }
        self._emit("ransomware_esxi", "critical", detail)
        return detail


# ---------------------------------------------------------------------------
# Slow-burn encryption detector  (review gap: throttled ransomware evades 3-sigma)
# ---------------------------------------------------------------------------

class SlowBurnDetector:
    """Sigma-independent. Counts confirmed plaintext->ciphertext transitions
    over a long window. Ransomware throttled to evade burst detection still
    has to encrypt every file eventually; this catches the cumulative total.
    """

    def __init__(self, emit, store: Optional[BaselineStore] = None,
                 window: int = SLOWBURN_WINDOW, min_transitions: int = SLOWBURN_MIN_TRANSITIONS):
        self._emit = emit
        self.window = window
        self.min_transitions = min_transitions
        self._transitions: deque = deque()
        self._fired_at = 0.0
        self._store = store
        if store:
            for ts in store.get("slowburn_transitions", []) or []:
                try:
                    self._transitions.append(float(ts))
                except (TypeError, ValueError):
                    continue

    def record_transition(self) -> None:
        self._transitions.append(time.time())

    def evaluate(self) -> Optional[Dict]:
        now = time.time()
        while self._transitions and self._transitions[0] < now - self.window:
            self._transitions.popleft()
        count = len(self._transitions)
        if count < self.min_transitions:
            return None
        if now - self._fired_at < self.window / 4:
            return None
        self._fired_at = now
        rate = count / (self.window / 60.0)
        detail = {
            "reason": "slow_burn_encryption",
            "transitions": count,
            "window_seconds": self.window,
            "files_per_minute": round(rate, 2),
            "message": (f"{count} plaintext->ciphertext transitions over "
                        f"{self.window // 60}min ({rate:.1f}/min) — throttled "
                        f"encryption below burst threshold"),
        }
        self._emit("slow_encrypt", "critical", detail)
        return detail

    def persist(self) -> None:
        if self._store:
            self._store.set("slowburn_transitions", list(self._transitions)[-5000:])


# ---------------------------------------------------------------------------
# Egress volume monitor  (review gap: cloud_exfil had no live emitter at all)
# ---------------------------------------------------------------------------

class EgressVolumeMonitor:
    """Detects bulk outbound data transfer by VOLUME, not by process name.

    This is the fix for the review's core objection: matching on 'rclone' is
    defeated by renaming the binary, and cloud exfil rides port 443 which the
    existing SocketMonitor explicitly treats as benign. Here the measured
    signal is bytes leaving the box over a rolling window; the process name is
    only ever supporting context.
    """

    def __init__(self, emit, window: int = EGRESS_WINDOW,
                 bytes_threshold: int = EGRESS_BYTES_THRESHOLD,
                 store: Optional[BaselineStore] = None):
        self._emit = emit
        self.window = window
        self.bytes_threshold = bytes_threshold
        self._samples: deque = deque()        # (ts, bytes_sent_total)
        self._fired_at = 0.0
        self._store = store
        self._last_total: Optional[int] = None

    def _current_bytes_sent(self) -> Optional[int]:
        if psutil is None:
            return None
        try:
            return int(psutil.net_io_counters().bytes_sent)
        except Exception:
            return None

    def _candidate_processes(self) -> List[Dict]:
        """Non-allowlisted processes holding ESTABLISHED outbound sockets."""
        if psutil is None:
            return []
        candidates: Dict[int, Dict] = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != "ESTABLISHED" or not conn.raddr or not conn.pid:
                    continue
                if conn.raddr.ip.startswith(("127.", "10.", "192.168.", "169.254.")):
                    continue
                try:
                    proc = psutil.Process(conn.pid)
                    name = (proc.name() or "").lower()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                if name in EGRESS_ALLOWLIST:
                    continue
                entry = candidates.setdefault(conn.pid, {
                    "pid": conn.pid, "name": name,
                    "bulk_transfer_hint": any(h in name for h in BULK_TRANSFER_HINTS),
                    "destinations": [],
                })
                dest = f"{conn.raddr.ip}:{conn.raddr.port}"
                if dest not in entry["destinations"]:
                    entry["destinations"].append(dest)
        except (psutil.AccessDenied, PermissionError, Exception):
            return list(candidates.values())
        return list(candidates.values())

    def sample(self) -> None:
        total = self._current_bytes_sent()
        if total is None:
            return
        self._samples.append((time.time(), total))

    def evaluate(self) -> Optional[Dict]:
        now = time.time()
        while self._samples and self._samples[0][0] < now - self.window:
            self._samples.popleft()
        if len(self._samples) < EGRESS_SUSTAINED_SAMPLES:
            return None

        first_ts, first_total = self._samples[0]
        last_ts, last_total = self._samples[-1]
        delta = last_total - first_total
        if delta < 0:                      # counter reset (reboot / iface flap)
            self._samples.clear()
            return None
        if delta < self.bytes_threshold:
            return None
        if now - self._fired_at < self.window:
            return None

        candidates = self._candidate_processes()
        self._fired_at = now
        elapsed = max(1.0, last_ts - first_ts)
        detail = {
            "reason": "bulk_egress_volume",
            "bytes_out": delta,
            "megabytes_out": round(delta / (1024 * 1024), 1),
            "window_seconds": int(elapsed),
            "throughput_mbps": round((delta * 8) / elapsed / 1_000_000, 2),
            "attribution": "correlational",
            "candidate_processes": candidates[:5],
            "bulk_client_seen": any(c.get("bulk_transfer_hint") for c in candidates),
            "message": (f"{delta / (1024*1024):.0f} MB egress in {int(elapsed)}s — "
                        f"possible double-extortion data theft"),
        }
        self._emit("cloud_exfil", "high", detail)
        return detail

    def persist(self) -> None:
        if self._store:
            self._store.set("egress_last_fired", self._fired_at)
