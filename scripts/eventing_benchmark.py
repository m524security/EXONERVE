#!/usr/bin/env python3
"""
Exonerve :: Poll vs Event FilesystemMonitor Benchmark  (v3.10, Priority 1.1)
==================================================================================
EXONERVE_NEXT_UPDATE_PROMPT.md, 1.1 definition of done: "Documented CPU/memory
comparison: polling vs eventing, at idle and under load."

HONESTY NOTE, read before trusting these numbers: this is a single-machine,
single-run measurement in whatever sandbox it happens to execute in — NOT a
production-scale benchmark, and not something to cite as an absolute
guarantee of resource usage on a real host. It exists to demonstrate the
SHAPE of the difference (poll cost scales with tree size regardless of
activity; event cost scales with actual change volume), which is the
architectural property Priority 1.1 exists to fix. For real capacity
planning, re-run this against a representative filesystem on the target
hardware — this script is built to make that easy (see --files/--changes).

Two scenarios, each run once per mode:

  IDLE   : monitor a tree of --files pre-existing files, nothing changes,
           for --duration seconds. Poll mode still walks the whole tree on
           every tick; event mode should be near-silent.

  UNDER LOAD : same tree, but --changes files get modified partway through.
           Compares how quickly + how expensively each mode notices.

Usage:
    python3 scripts/eventing_benchmark.py --files 2000 --changes 200 --duration 10
"""
from __future__ import annotations

import argparse
import os
import sys
import time
import tempfile
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "guest_production_vm"))

import psutil  # noqa: E402
import sentry_agent as sa  # noqa: E402
from ransomware_sensors import EntropyTransitionTracker  # noqa: E402


class _Tunnel:
    def __init__(self):
        self.vm_id = "bench"

    def enqueue(self, event):
        pass


def _build_tree(root: str, n_files: int):
    for i in range(n_files):
        with open(os.path.join(root, f"file_{i}.txt"), "w") as f:
            f.write(f"benchmark content {i}\n" * 5)


def _make_monitor(root: str, mode: str):
    tunnel = _Tunnel()
    return sa.FilesystemMonitor(
        root, entropy_threshold=7.2, velocity_window=30, velocity_threshold=999999,
        tunnel=tunnel, crypto_detector=sa.CryptographicSpikeDetector(tunnel),
        transitions=EntropyTransitionTracker(), mode=mode,
    )


def _measure(root: str, mode: str, duration: float, poll_interval: float,
             n_changes: int) -> dict:
    proc = psutil.Process(os.getpid())
    monitor = _make_monitor(root, mode)
    monitor.start()
    if monitor.mode != mode:
        print(f"  [!] requested mode={mode!r} but monitor fell back to "
              f"mode={monitor.mode!r} (see console for why)")

    proc.cpu_percent(interval=None)   # prime the counter (first call is meaningless)
    mem_before = proc.memory_info().rss
    t0 = time.time()
    ticks = 0
    changed_at = t0 + duration * 0.4
    did_change = False

    while time.time() - t0 < duration:
        if not did_change and time.time() >= changed_at:
            files = sorted(os.listdir(root))[:n_changes]
            for name in files:
                with open(os.path.join(root, name), "a") as f:
                    f.write("MODIFIED\n")
            did_change = True
            change_ts = time.time()
        monitor.scan()
        ticks += 1
        time.sleep(poll_interval)

    cpu_pct = proc.cpu_percent(interval=None)
    mem_after = proc.memory_info().rss
    monitor.stop()

    return {
        "mode": monitor.mode,
        "ticks": ticks,
        "cpu_percent_avg": cpu_pct,
        "rss_delta_kb": (mem_after - mem_before) / 1024.0,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--files", type=int, default=2000)
    ap.add_argument("--changes", type=int, default=200)
    ap.add_argument("--duration", type=float, default=10.0)
    ap.add_argument("--poll-interval", type=float, default=2.0)
    args = ap.parse_args()

    if not sa.WATCHDOG_AVAILABLE:
        print("watchdog is not installed — event mode would just fall back to "
              "poll mode, so this comparison would be meaningless. Install "
              "`watchdog` and re-run.")
        sys.exit(1)

    results = {}
    for mode in ("poll", "event"):
        tmp = tempfile.mkdtemp(prefix=f"exonerve_bench_{mode}_")
        try:
            print(f"[*] Building {args.files}-file tree for mode={mode} ...")
            _build_tree(tmp, args.files)
            print(f"[*] Running {args.duration:.0f}s ({args.changes} files "
                  f"modified partway through) ...")
            results[mode] = _measure(tmp, mode, args.duration, args.poll_interval,
                                      args.changes)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    print("\n=== Results (single-run, this sandbox — see module docstring) ===")
    print(f"{'mode':<8}{'ticks':<8}{'avg cpu%':<12}{'rss delta (KB)':<16}")
    for mode, r in results.items():
        print(f"{r['mode']:<8}{r['ticks']:<8}{r['cpu_percent_avg']:<12.2f}"
              f"{r['rss_delta_kb']:<16.1f}")
    print("\nExpected shape: poll's cost is roughly constant per tick "
          "REGARDLESS of whether anything changed (it walks the whole tree "
          "either way); event's cost should track actual change volume, "
          "with near-zero overhead while idle.")


if __name__ == "__main__":
    main()
