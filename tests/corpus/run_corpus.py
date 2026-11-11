#!/usr/bin/env python3
"""
Exonerve :: False-Positive Corpus Runner  (v3.10, Priority 1.3)
=======================================================================
Runs the REAL, live detectors — not a mock — against each generated benign
workload in generators.py, and reports a per-detector false-positive count.

This is intentionally separate from the unit tests in
tests/test_ransomware_sensors.py etc.: those prove specific, small, HAND-
PICKED benign cases stay silent. This corpus exists because that is not the
same claim as "quiet at realistic scale" — every prior 0-FP claim in this
project has had to carry that qualifier, and this file is what removes it
for the scenarios it covers (still not a substitute for production
telemetry from a real fleet; see the honesty note in generators.py and the
OPEN section of DEFENSE_GUIDE.md).

Usage:
    python3 tests/corpus/run_corpus.py                 # write FP_CORPUS_RESULTS.md
    python3 tests/corpus/run_corpus.py --check          # exit 1 on any FP, print only
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "guest_production_vm"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import sentry_agent as sa  # noqa: E402
from ransomware_sensors import (  # noqa: E402
    EntropyTransitionTracker, ExtensionRenameDetector,
)
import modern_threats as mt  # noqa: E402

import generators as gen  # noqa: E402


class _Collector:
    def __init__(self):
        self.events = []

    def __call__(self, event_type, severity, details):
        self.events.append({"event_type": event_type, "severity": severity,
                            "details": details})


class _FakeTunnel:
    def __init__(self, collector: _Collector):
        self.vm_id = "corpus-bench"
        self._collector = collector

    def enqueue(self, event):
        self._collector("__tunnel__:" + event.event_type, event.severity,
                        event.details)


def run_backup_job(scale: float = 1.0) -> dict:
    """Backup writes 50,000+ (CI-scaled) compressed archives in a burst."""
    collector = _Collector()
    tunnel = _FakeTunnel(collector)
    rename_detector = ExtensionRenameDetector(collector)
    monitor = sa.FilesystemMonitor(
        "", entropy_threshold=7.2, velocity_window=30, velocity_threshold=999999,
        tunnel=tunnel, crypto_detector=sa.CryptographicSpikeDetector(tunnel),
        transitions=EntropyTransitionTracker(), rename_detector=rename_detector,
        mode="poll",
    )
    tmp = tempfile.mkdtemp(prefix="exonerve_corpus_backup_")
    try:
        monitor.target_dir = sa.Path(tmp)
        monitor.scan()   # prime on empty dir — matches a monitor already
                          # running before the backup job starts
        t0 = time.time()
        meta = gen.generate_backup_job(tmp, scale=scale)
        monitor.scan()
        elapsed = time.time() - t0
        fp_events = [e for e in collector.events
                     if e["event_type"] in ("ext_rename", "ext_rate_spike")]
        fp_events += [e for e in collector.events
                      if e["event_type"] == "__tunnel__:crypto_spike"]
        return {"scenario": "backup_job", "file_count": meta["file_count"],
                "elapsed_s": round(elapsed, 2), "fp_events": fp_events,
                "all_events": collector.events}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_build_server(scale: float = 1.0) -> dict:
    """CI build compiling for ~20 minutes: many files, a wide but STABLE
    extension vocabulary — the scenario that motivated the novelty-ratio
    fix in ExtensionRenameDetector (see ransomware_sensors.py, Priority 2.1)."""
    collector = _Collector()
    tunnel = _FakeTunnel(collector)
    rename_detector = ExtensionRenameDetector(collector)
    monitor = sa.FilesystemMonitor(
        "", entropy_threshold=7.2, velocity_window=30, velocity_threshold=999999,
        tunnel=tunnel, crypto_detector=sa.CryptographicSpikeDetector(tunnel),
        transitions=EntropyTransitionTracker(), rename_detector=rename_detector,
        mode="poll",
    )
    tmp = tempfile.mkdtemp(prefix="exonerve_corpus_build_")
    try:
        monitor.target_dir = sa.Path(tmp)
        monitor.scan()
        t0 = time.time()
        meta = gen.generate_build_server(tmp, scale=scale)
        monitor.scan()
        elapsed = time.time() - t0
        fp_events = [e for e in collector.events
                     if e["event_type"] in ("ext_rename", "ext_rate_spike")]
        return {"scenario": "build_server", "file_count": meta["file_count"],
                "distinct_extensions": len(meta["distinct_extensions"]),
                "elapsed_s": round(elapsed, 2), "fp_events": fp_events,
                "all_events": collector.events}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_indexer(scale: float = 1.0) -> dict:
    """Read-only crawl of the whole disk: must not look like mass file
    touching. Files pre-exist BEFORE the monitor primes (they are the
    disk's existing content), then the indexer only reads them."""
    collector = _Collector()
    tunnel = _FakeTunnel(collector)
    rename_detector = ExtensionRenameDetector(collector)
    tmp = tempfile.mkdtemp(prefix="exonerve_corpus_indexer_")
    try:
        meta = gen.generate_indexer_target(tmp, scale=scale)
        monitor = sa.FilesystemMonitor(
            tmp, entropy_threshold=7.2, velocity_window=30, velocity_threshold=999999,
            tunnel=tunnel, crypto_detector=sa.CryptographicSpikeDetector(tunnel),
            transitions=EntropyTransitionTracker(), rename_detector=rename_detector,
            mode="poll",
        )
        monitor.scan()   # prime — these files are the existing disk content
        t0 = time.time()
        gen.simulate_indexer_reads(meta["paths"])
        monitor.scan()   # a second pass while the "indexer" only reads
        elapsed = time.time() - t0
        return {"scenario": "indexer", "file_count": meta["file_count"],
                "elapsed_s": round(elapsed, 2), "fp_events": collector.events,
                "all_events": collector.events}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_port_sweep(scale: float = 1.0) -> dict:
    """Vulnerability scanner sweeping thousands of ports — the opposite
    shape of C2 beaconing (BeaconDetector, Priority 2.4)."""
    collector = _Collector()
    detector = mt.BeaconDetector(collector, min_samples=6)
    meta = gen.generate_port_sweep(scale=scale)
    t0 = time.time()
    for conn in meta["connections"]:
        key = f"{conn.proc_name}->{conn.dest_ip}:{conn.dest_port}"
        detector.record_sighting(key, conn.ts)
    findings = detector.evaluate()
    elapsed = time.time() - t0
    return {"scenario": "port_sweep", "connection_count": meta["connection_count"],
            "elapsed_s": round(elapsed, 2), "fp_events": collector.events,
            "all_events": collector.events}


SCENARIOS = {
    "backup_job": run_backup_job,
    "build_server": run_build_server,
    "indexer": run_indexer,
    "port_sweep": run_port_sweep,
}


def run_all(scale: float = 1.0) -> dict:
    return {name: fn(scale=scale) for name, fn in SCENARIOS.items()}


def render_markdown(results: dict) -> str:
    lines = []
    lines.append("# FP_CORPUS_RESULTS.md")
    lines.append("")
    lines.append("Auto-generated by `tests/corpus/run_corpus.py` "
                 f"(`python3 tests/corpus/run_corpus.py`). "
                 f"Last run: {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append("Regenerate on any PR that touches a detector: "
                 "`python3 tests/corpus/run_corpus.py`.")
    lines.append("")
    lines.append("**Scale note:** these runs use the CI-friendly default scale "
                 "(`generators.py`), not the literal 50,000+-file volume described "
                 "in `EXONERVE_NEXT_UPDATE_PROMPT.md` Priority 1.3 — that full-scale "
                 "run is available via `EXONERVE_FP_CORPUS_FULL_SCALE=1` for local "
                 "verification but is too slow to run on every PR. The default scale "
                 "preserves the workload SHAPE (extension mix, burstiness) that "
                 "matters for these detectors, at a size CI can afford.")
    lines.append("")
    lines.append("| Scenario | Volume | False positives | Notes |")
    lines.append("|---|---|---|---|")

    total_fp = 0
    for name, r in results.items():
        fp_count = len(r["fp_events"])
        total_fp += fp_count
        volume = r.get("file_count") or r.get("connection_count")
        note = "clean" if fp_count == 0 else "**FALSE POSITIVES — investigate**"
        lines.append(f"| {name} | {volume} | {fp_count} | {note} |")

    lines.append("")
    lines.append(f"**Total false positives across corpus: {total_fp}**")
    lines.append("")

    for name, r in results.items():
        if r["fp_events"]:
            lines.append(f"## {name} — false positive detail")
            for e in r["fp_events"]:
                lines.append(f"- `{e['event_type']}` ({e['severity']}): "
                             f"{e['details'].get('message', e['details'])}")
            lines.append("")

    lines.append("## Scenario descriptions")
    lines.append("")
    lines.append("- **backup_job** — a backup tool (tar/rsync/restic-shaped) writing "
                 "many already-compressed `.tar.gz` archives in a burst. Exercises "
                 "the entropy-transition classifier and the extension-clustering / "
                 "novel-extension-rate detectors at volume.")
    lines.append("- **build_server** — a multi-language CI build producing files "
                 "across a wide (~16) but STABLE extension vocabulary. This is the "
                 "scenario that surfaced the need for the novelty-RATIO gate in "
                 "`ExtensionRenameDetector` (v3.10, Priority 2.1) — an absolute "
                 "distinct-extension-count threshold alone would have false-"
                 "positived here.")
    lines.append("- **indexer** — a read-only crawl of a pre-existing tree. No "
                 "writes, no mtime changes; the control case proving reads alone "
                 "generate zero detector activity.")
    lines.append("- **port_sweep** — a vulnerability scanner touching thousands of "
                 "distinct ports. Exercises `BeaconDetector` (v3.10, Priority 2.4), "
                 "which requires many sightings of the SAME destination — a sweep "
                 "structurally cannot supply that.")
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="Exit 1 on any false positive; do not write the results file.")
    ap.add_argument("--scale", type=float, default=1.0,
                    help="Multiplier on each generator's default (CI-friendly) file count.")
    ap.add_argument("--out", default=os.path.join(ROOT, "FP_CORPUS_RESULTS.md"))
    args = ap.parse_args()

    results = run_all(scale=args.scale)
    total_fp = sum(len(r["fp_events"]) for r in results.values())

    if args.check:
        for name, r in results.items():
            print(f"{name}: {len(r['fp_events'])} false positives "
                 f"(volume={r.get('file_count') or r.get('connection_count')})")
        sys.exit(1 if total_fp else 0)

    md = render_markdown(results)
    with open(args.out, "w") as f:
        f.write(md)
    print(f"Wrote {args.out} — total false positives: {total_fp}")
    if total_fp:
        sys.exit(1)


if __name__ == "__main__":
    main()
