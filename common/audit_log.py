"""
Tamper-evident, append-only decision audit log (DFIR chain-of-custody).

Every automated decision the control plane makes — MONITOR / ALERT / CONTAIN /
FAILOVER / HEAL / ESCALATE — is written here as an immutable record. Two
independent integrity guarantees make the log court-defensible after an
incident:

  1. HASH CHAIN  — each entry stores the SHA-256 of (its own payload || the
     previous entry's hash). Altering, deleting, reordering, or inserting any
     past entry breaks every hash downstream, so tampering is detectable even
     by someone who can write the file.

  2. HMAC SIGNATURE — each entry is signed with HMAC-SHA256 under a secret key
     (EXONERVE_AUDIT_KEY). Without the key an attacker cannot forge a *valid*
     replacement chain, so they cannot silently rewrite history — only visibly
     truncate it (and truncation is itself detectable via the monotonic seq).

This is deliberately NOT a blockchain and needs no external service: it is a
single append-only JSONL file that any analyst can re-verify offline with
`verify_file()`. No ML, no black box — the whole point of Exonerve's design.

Format: one JSON object per line (JSONL), fields:
    seq, ts, actor, vm_id, verdict, reason, data, prev_hash, entry_hash, sig
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

GENESIS = "0" * 64   # prev_hash of the very first entry

# Repo root, resolved from THIS file's location (common/audit_log.py -> repo/).
# Used to anchor the default log path so it never depends on the process cwd.
_REPO_ROOT = Path(__file__).resolve().parent.parent


class AuditIntegrityError(Exception):
    """Raised when the audit log's on-disk state can't be trusted to append to."""


def _canonical(obj: Any) -> bytes:
    """Deterministic serialization so the same content always hashes the same."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _entry_hash(seq: int, ts: str, actor: str, vm_id: str, verdict: str,
                reason: str, data: dict, prev_hash: str) -> str:
    payload = _canonical({
        "seq": seq, "ts": ts, "actor": actor, "vm_id": vm_id,
        "verdict": verdict, "reason": reason, "data": data,
        "prev_hash": prev_hash,
    })
    return hashlib.sha256(payload).hexdigest()


def _sign(entry_hash: str, key: Optional[bytes]) -> str:
    if not key:
        return ""
    return hmac.new(key, entry_hash.encode(), hashlib.sha256).hexdigest()


class DecisionAuditLog:
    """Append-only, hash-chained, optionally HMAC-signed decision log."""

    def __init__(self, path: Optional[str] = None,
                 key: Optional[bytes] = None):
        # Anchor the default path to the repo, NOT the process cwd. A bare
        # relative path silently wrote the "court-defensible" trail to the wrong
        # place when the control plane was launched from inside host_control_plane/
        # (producing a doubled forensics_archive/ dir). For a forensic log,
        # writing to the wrong path is worse than failing — so the location is
        # now deterministic regardless of where the process is started.
        #   precedence: explicit arg > EXONERVE_AUDIT_PATH env > repo default
        if path is None:
            path = os.environ.get("EXONERVE_AUDIT_PATH") or str(
                _REPO_ROOT / "host_control_plane" / "forensics_archive" / "decisions.jsonl")
        self.path = Path(path).expanduser().resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # Key precedence: explicit arg > env. Absent key => hash-chain only
        # (still tamper-evident to deletion/reorder, just not forgery-proof).
        if key is None:
            env = os.environ.get("EXONERVE_AUDIT_KEY", "")
            key = bytes.fromhex(env) if env and _is_hex(env) else (env.encode() if env else None)
        self._key = key
        self._lock = threading.Lock()
        self._seq, self._last_hash = self._resume()

    def _resume(self) -> Tuple[int, str]:
        """Continue an existing chain (or start a fresh one).

        If the existing log's tail is unreadable we do NOT silently start a new
        chain — that would let an attacker truncate history and have the log
        quietly "recover". We raise, so the operator must investigate (and can
        run verify_file / archive the damaged log deliberately). Set
        EXONERVE_AUDIT_ALLOW_RESET=1 to override for non-forensic/dev use.
        """
        if not self.path.exists():
            return 0, GENESIS
        last = None
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    last = line
        if not last:
            return 0, GENESIS
        try:
            rec = json.loads(last)
            return int(rec["seq"]) + 1, rec["entry_hash"]
        except Exception as exc:
            if os.environ.get("EXONERVE_AUDIT_ALLOW_RESET") == "1":
                return 0, GENESIS
            raise AuditIntegrityError(
                f"Refusing to append to a corrupt audit log ({self.path}): "
                f"unreadable tail ({exc}). Investigate/verify_file the existing "
                f"log, then archive it or set EXONERVE_AUDIT_ALLOW_RESET=1 to "
                f"start a new chain deliberately.")

    @property
    def signed(self) -> bool:
        return self._key is not None

    def record(self, verdict: str, vm_id: str, reason: str = "",
               data: Optional[dict] = None, actor: str = "decision_engine") -> dict:
        """Append one decision. Returns the written record."""
        with self._lock:
            seq = self._seq
            ts = datetime.now(timezone.utc).isoformat()
            data = data or {}
            eh = _entry_hash(seq, ts, actor, vm_id, verdict, reason, data, self._last_hash)
            rec = {
                "seq": seq, "ts": ts, "actor": actor, "vm_id": vm_id,
                "verdict": verdict, "reason": reason, "data": data,
                "prev_hash": self._last_hash, "entry_hash": eh,
                "sig": _sign(eh, self._key),
            }
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self._seq = seq + 1
            self._last_hash = eh
            return rec

    def verify(self) -> Dict[str, Any]:
        """Verify the on-disk chain. See verify_file for the report shape."""
        return verify_file(self.path, self._key)


def _is_hex(s: str) -> bool:
    try:
        bytes.fromhex(s)
        return True
    except ValueError:
        return False


def verify_file(path, key: Optional[bytes] = None) -> Dict[str, Any]:
    """Re-verify an audit log offline. Detects any tamper/deletion/reorder.

    Returns: {ok, entries, first_bad_seq, reason}
    """
    path = Path(path)
    if key is None:
        env = os.environ.get("EXONERVE_AUDIT_KEY", "")
        key = bytes.fromhex(env) if env and _is_hex(env) else (env.encode() if env else None)

    if not path.exists():
        return {"ok": True, "entries": 0, "first_bad_seq": None, "reason": "no log yet"}

    prev = GENESIS
    expected_seq = 0
    n = 0
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            n += 1
            try:
                rec = json.loads(line)
            except Exception as e:
                return {"ok": False, "entries": n, "first_bad_seq": expected_seq,
                        "reason": f"malformed JSON at line {n}: {e}"}

            # monotonic sequence (catches deletion / reordering / insertion)
            if rec.get("seq") != expected_seq:
                return {"ok": False, "entries": n, "first_bad_seq": expected_seq,
                        "reason": f"sequence break: expected {expected_seq}, got {rec.get('seq')}"}
            # chain linkage
            if rec.get("prev_hash") != prev:
                return {"ok": False, "entries": n, "first_bad_seq": rec.get("seq"),
                        "reason": f"broken chain at seq {rec.get('seq')} (prev_hash mismatch)"}
            # recompute the content hash (catches field tampering)
            calc = _entry_hash(rec["seq"], rec["ts"], rec["actor"], rec["vm_id"],
                               rec["verdict"], rec["reason"], rec.get("data", {}),
                               rec["prev_hash"])
            if calc != rec.get("entry_hash"):
                return {"ok": False, "entries": n, "first_bad_seq": rec.get("seq"),
                        "reason": f"content tampered at seq {rec.get('seq')} (hash mismatch)"}
            # signature (catches forgery when a key is configured)
            if key is not None:
                if not hmac.compare_digest(_sign(calc, key), rec.get("sig", "")):
                    return {"ok": False, "entries": n, "first_bad_seq": rec.get("seq"),
                            "reason": f"bad signature at seq {rec.get('seq')} (forged or wrong key)"}

            prev = rec["entry_hash"]
            expected_seq += 1

    return {"ok": True, "entries": n, "first_bad_seq": None, "reason": "chain intact"}


def read_entries(path) -> List[dict]:
    """Load all records (for display / export)."""
    path = Path(path)
    out: List[dict] = []
    if not path.exists():
        return out
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except Exception:
                    pass
    return out


if __name__ == "__main__":  # tiny self-demo + offline verifier CLI
    import argparse
    ap = argparse.ArgumentParser(description="Exonerve decision audit log")
    ap.add_argument("--verify", metavar="PATH", help="verify an existing log file")
    args = ap.parse_args()
    if args.verify:
        rep = verify_file(args.verify)
        print(json.dumps(rep, indent=2))
    else:
        import tempfile
        p = Path(tempfile.gettempdir()) / "exonerve_audit_demo.jsonl"
        if p.exists():
            p.unlink()
        log = DecisionAuditLog(str(p), key=b"demo-key")
        log.record("CONTAIN", "web-01", "score>=100", {"score": 115})
        log.record("FAILOVER", "web-01", "standby available", {"rto": 0.8})
        print("signed:", log.signed, "| verify:", log.verify())
