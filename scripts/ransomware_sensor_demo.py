#!/usr/bin/env python3
"""
Exonerve :: Ransomware Sensor End-to-End Demo
=================================================
Runs the REAL sensors against a REAL filesystem — no injected events.

This exists because an external review correctly pointed out that
`attack_replay.py` proves the *scoring pipeline*, not the *sensor chain*: it
hand-feeds synthetic events into the control plane. This script instead
performs actual file I/O and lets the actual FilesystemMonitor observe it.

Two phases, and the contrast between them is the whole point:

  PHASE 1 (BENIGN)     A backup job writes compressed archives. Content is
                       ~8.0-bit entropy — indistinguishable from ciphertext by
                       absolute measure. Correct behaviour: NO ransomware alert.

  PHASE 2 (RANSOMWARE) Documents are encrypted in place and renamed to
                       '.locked'. Correct behaviour: crypto/entropy alerts AND
                       an ext_rename alert.

Usage:  python3 scripts/ransomware_sensor_demo.py
Exit 0 if the sensors behave correctly, 1 otherwise (CI-friendly).
"""

import os
import sys
import time
import zlib
import shutil
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "guest_production_vm"))

from ransomware_sensors import (  # noqa: E402
    EntropyTransitionTracker, ExtensionRenameDetector,
    EsxiEncryptionDetector, SlowBurnDetector,
)

G = "\033[92m"; R = "\033[91m"; C = "\033[96m"; D = "\033[2m"; X = "\033[0m"


class FakeTunnel:
    """Stands in for the encrypted telemetry tunnel; records what would ship."""
    vm_id = "demo-vm"

    def __init__(self):
        self.events = []

    def enqueue(self, event):
        self.events.append(event)

    def types(self):
        return [e.event_type for e in self.events]


def write_document(path: Path, n: int = 40_000):
    """Ordinary business text — low entropy, like a real document."""
    body = ("Quarterly revenue report. All figures in thousands of dollars. "
            "Prepared by the finance team for internal review. ") * (n // 110 + 1)
    path.write_text(body[:n], encoding="utf-8")


def write_compressed_archive(path: Path, n: int = 40_000):
    """A backup artifact: legitimately ~8.0-bit entropy after compression."""
    body = os.urandom(n)              # already-compressed data is ~random
    path.write_bytes(zlib.compress(body, 9))


def encrypt_in_place(path: Path):
    """Simulated ransomware: overwrite with ciphertext-like bytes."""
    size = path.stat().st_size
    path.write_bytes(os.urandom(max(size, 4096)))


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="exonerve-demo-"))
    ok = True
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "sentry_agent", str(ROOT / "guest_production_vm" / "sentry_agent.py"))
        sentry = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(sentry)

        def build_monitor(tunnel):
            transitions = EntropyTransitionTracker()
            crypto = sentry.CryptographicSpikeDetector(tunnel, target_dir=str(tmp))
            emit = lambda t, s, d: tunnel.enqueue(   # noqa: E731
                sentry.TelemetryEvent(tunnel.vm_id, "now", t, s, 0, d))
            return sentry.FilesystemMonitor(
                str(tmp), 7.2, 30, 10, tunnel, crypto,
                transitions=transitions,
                rename_detector=ExtensionRenameDetector(emit, min_files=12),
                esxi_detector=EsxiEncryptionDetector(emit),
                slowburn_detector=SlowBurnDetector(emit)), transitions

        print(f"\n{C}══ EXONERVE RANSOMWARE SENSOR — END-TO-END DEMO ══{X}")
        print(f"{D}sandbox: {tmp}{X}\n")

        # ---------------- PHASE 1 : benign backup workload -----------------
        print(f"{C}PHASE 1 — BENIGN: backup job writing compressed archives{X}")
        tunnel = FakeTunnel()
        monitor, _ = build_monitor(tunnel)

        for i in range(25):
            write_compressed_archive(tmp / f"backup_{i}.tar.gz")
        monitor.scan()                      # prime inventory
        time.sleep(0.05)
        for i in range(25):                 # nightly re-run rewrites them
            write_compressed_archive(tmp / f"backup_{i}.tar.gz")
        monitor.scan()

        benign_alerts = [t for t in tunnel.types()
                         if t in ("crypto_spike", "entropy", "ext_rename", "slow_encrypt")]
        if benign_alerts:
            print(f"  {R}FAIL{X}  backup job raised {len(benign_alerts)} ransomware "
                  f"alert(s): {sorted(set(benign_alerts))}")
            print(f"  {D}      this is the false positive the fix was meant to remove{X}")
            ok = False
        else:
            print(f"  {G}PASS{X}  50 high-entropy archive writes -> "
                  f"{G}0 ransomware alerts{X}")
            print(f"  {D}      absolute entropy ~8.0 but no plaintext->ciphertext "
                  f"transition{X}")

        # ---------------- PHASE 2 : real ransomware behaviour --------------
        print(f"\n{C}PHASE 2 — RANSOMWARE: encrypt documents + rename to .locked{X}")
        shutil.rmtree(tmp); tmp.mkdir()
        tunnel = FakeTunnel()
        monitor, _ = build_monitor(tunnel)

        docs = []
        for i in range(30):
            p = tmp / f"report_{i}.docx"
            write_document(p)
            docs.append(p)
        monitor.scan()                      # learns these are plaintext
        time.sleep(0.05)

        for p in docs:                      # detonate
            encrypt_in_place(p)
            p.rename(p.with_suffix(".locked"))
        monitor.scan()

        fired = set(tunnel.types())
        got_encryption = bool({"entropy", "crypto_spike"} & fired)
        got_rename = "ext_rename" in fired

        if got_encryption:
            print(f"  {G}PASS{X}  encryption detected -> "
                  f"{sorted({'entropy','crypto_spike'} & fired)}")
        else:
            print(f"  {R}FAIL{X}  encryption of 30 documents produced no alert")
            ok = False

        if got_rename:
            ev = next(e for e in tunnel.events if e.event_type == "ext_rename")
            print(f"  {G}PASS{X}  mass rename detected -> "
                  f"{ev.details['file_count']} x '{ev.details['extension']}'")
        else:
            print(f"  {R}FAIL{X}  mass rename to .locked produced no alert")
            ok = False

        print(f"\n{C}══ RESULT ══{X}")
        if ok:
            print(f"  {G}SENSORS CORRECT{X} — silent on benign compression, "
                  f"loud on real encryption\n")
        else:
            print(f"  {R}SENSOR REGRESSION{X}\n")
        return 0 if ok else 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
