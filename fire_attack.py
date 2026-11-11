#!/usr/bin/env python3
"""
Exonerve :: fire_attack.py
==============================
Hand-craft ONE attack event and send it over the REAL authenticated secure
channel to a running control_center.py — exercising the full pipeline:
crypto seal -> socket -> auth/replay check -> scoring -> Sigma match ->
ATT&CK mapping -> decision engine -> dashboard.

Usage (two terminals, same venv activated in both):

  Terminal 1:
    $env:EXONERVE_API_TOKEN = (python -c "import secrets;print(secrets.token_urlsafe(24))")
    python host_control_plane\\control_center.py --api-token $env:EXONERVE_API_TOKEN

  Terminal 2 (from the repo root):
    python fire_attack.py                       # fires ransomware by default
    python fire_attack.py --attack lolbin       # fire a specific case
    python fire_attack.py --list                # show all available attacks
    python fire_attack.py --vm my-test-vm --attack cred_dump

Then open http://127.0.0.1:5000 in a browser (enter the token when prompted)
and watch the alert, threat score, and decision explanation appear live.
"""
from __future__ import annotations

import argparse
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common.secure_channel import SecureSender, load_master_secret  # noqa: E402

ATTACKS = {
    "ransomware": {"event_type": "crypto_spike", "severity": "critical",
                   "details": {"reason": "mass_encryption", "files_touched": 4200}},
    "cred_dump": {"event_type": "cred_dump", "severity": "critical",
                  "details": {"process": "lsass.exe", "technique": "T1003.001"}},
    "lolbin": {"event_type": "lolbin", "severity": "medium",
               "details": {"binary": "rundll32.exe", "technique": "T1218"}},
    "c2_beacon": {"event_type": "network", "severity": "high",
                  "details": {"dst_port": 4444, "jitter_ms": 12, "technique": "T1571"}},
    "webshell": {"event_type": "web_rce", "severity": "high",
                 "details": {"path": "/upload.php", "technique": "T1505.003"}},
    "heartbeat": {"event_type": "heartbeat", "severity": "low", "details": {}},
}


def main() -> int:
    ap = argparse.ArgumentParser(description="Fire one attack at a live Exonerve control plane")
    ap.add_argument("--attack", default="ransomware", choices=list(ATTACKS),
                     help="which attack case to send (default: ransomware)")
    ap.add_argument("--vm", default="test-vm-01", help="VM identity to attack as")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--list", action="store_true", help="list available attacks and exit")
    args = ap.parse_args()

    if args.list:
        print("Available --attack values:")
        for name, ev in ATTACKS.items():
            print(f"  {name:12} -> event_type={ev['event_type']!r} severity={ev['severity']!r}")
        return 0

    case = ATTACKS[args.attack]
    secret = load_master_secret()  # dev key unless EXONERVE_MASTER_KEY is set
    sender = SecureSender(secret, agent_id=args.vm)

    payload = {"vm_id": args.vm, "batch": [case]}
    frame = sender.seal(payload)

    print(f"Connecting to {args.host}:{args.port} ...")
    with socket.create_connection((args.host, args.port), timeout=5) as s:
        s.sendall(len(frame).to_bytes(4, "big") + frame)
        print(f"Sent '{args.attack}' as VM '{args.vm}': {case['event_type']} "
              f"({case['severity']})")
    print("Check the dashboard (http://127.0.0.1:5000) or the control plane's "
          "own console output for the alert + decision.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
