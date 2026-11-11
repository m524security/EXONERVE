#!/usr/bin/env python3
"""
Exonerve :: SIEM Export
===========================
Emits detections in the formats a real SOC already ingests, so Exonerve stops
being a standalone island (external-review gap: "no Splunk/Elastic/QRadar
output, alerts don't flow into the analyst's existing workflow").

Three wire formats, all dependency-free:

  * CEF (ArcSight Common Event Format)  -> QRadar, ArcSight, Splunk CIM add-ons
  * ECS-shaped JSON Lines               -> Elastic / OpenSearch / Filebeat
  * RFC 5424 syslog                     -> rsyslog / syslog-ng / any collector

Transport is deliberately boring: append to a file, or UDP/TCP to a collector.
No SDKs, no vendor lock-in, no network dependency at import time.

Failure policy: SIEM export must NEVER break detection. Every emit path is
wrapped; a dead collector degrades to a local file, and a dead file degrades
to a silent no-op with an internal counter the operator can inspect.
"""

from __future__ import annotations

import json
import os
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional

CEF_VERSION = "0"
CEF_VENDOR = "Exonerve"
CEF_PRODUCT = "Exonerve"

# severity word -> CEF 0..10 and syslog numeric severity
_SEVERITY_CEF = {"low": 2, "medium": 5, "high": 8, "critical": 10}
_SEVERITY_SYSLOG = {"low": 6, "medium": 4, "high": 3, "critical": 2}

# Characters that must be escaped inside a CEF extension value.
def _cef_escape(value: str) -> str:
    return (str(value).replace("\\", "\\\\")
            .replace("=", "\\=")
            .replace("\n", " ")
            .replace("\r", " "))


def _cef_header_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("|", "\\|")


def to_cef(event: Dict, product_version: str = "3.8.0") -> str:
    """Render a Exonerve detection as an ArcSight CEF line."""
    etype = event.get("event_type", "unknown")
    sev = str(event.get("severity", "medium")).lower()
    techniques = event.get("techniques") or []
    tech_ids = ",".join(t.get("id", "") if isinstance(t, dict) else str(t)
                        for t in techniques)
    details = event.get("details") or {}

    ext = {
        "rt": int(event.get("timestamp_epoch", time.time()) * 1000),
        "dvchost": event.get("vm_id", "unknown"),
        "cs1Label": "MitreTechniques", "cs1": tech_ids,
        "cs2Label": "DetectionReason", "cs2": details.get("reason", ""),
        "cs3Label": "Verdict", "cs3": event.get("verdict", ""),
        "cn1Label": "ThreatScore", "cn1": event.get("score", 0),
        "msg": details.get("message", event.get("title", etype)),
    }
    # Carry the numeric evidence an analyst needs to triage without pivoting.
    for key in ("file_count", "transitions", "bytes_out", "megabytes_out",
                "vm_artifact_count", "sigma_above_baseline", "extension"):
        if key in details:
            ext[key] = details[key]

    ext_str = " ".join(f"{k}={_cef_escape(v)}" for k, v in ext.items() if v != "")
    header = "|".join([
        f"CEF:{CEF_VERSION}",
        _cef_header_escape(CEF_VENDOR),
        _cef_header_escape(CEF_PRODUCT),
        _cef_header_escape(product_version),
        _cef_header_escape(etype),
        _cef_header_escape(event.get("title", etype)),
        str(_SEVERITY_CEF.get(sev, 5)),
    ])
    return f"{header}|{ext_str}"


def to_ecs_json(event: Dict) -> str:
    """Render as Elastic Common Schema JSON (one line, Filebeat-ready)."""
    details = event.get("details") or {}
    techniques = event.get("techniques") or []
    ts = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
    doc = {
        "@timestamp": ts,
        "event": {
            "kind": "alert",
            "category": ["intrusion_detection"],
            "module": "exonerve",
            "dataset": "exonerve.detection",
            "action": event.get("event_type"),
            "severity": _SEVERITY_CEF.get(str(event.get("severity", "medium")).lower(), 5),
            "risk_score": event.get("score", 0),
            "reason": details.get("message", ""),
        },
        "host": {"name": event.get("vm_id", "unknown")},
        "rule": {"name": event.get("title", event.get("event_type"))},
        "threat": {
            "framework": "MITRE ATT&CK",
            "technique": [
                {"id": t.get("id"), "name": t.get("name")}
                if isinstance(t, dict) else {"id": str(t)}
                for t in techniques
            ],
        },
        "exonerve": {
            "verdict": event.get("verdict"),
            "detection_reason": details.get("reason"),
            "details": details,
        },
    }
    return json.dumps(doc, separators=(",", ":"), default=str)


def to_syslog(event: Dict, hostname: Optional[str] = None,
              facility: int = 13) -> str:
    """Render as RFC 5424. facility 13 = log audit."""
    sev = _SEVERITY_SYSLOG.get(str(event.get("severity", "medium")).lower(), 5)
    pri = facility * 8 + sev
    ts = event.get("timestamp") or datetime.now(timezone.utc).isoformat()
    host = hostname or socket.gethostname()
    details = event.get("details") or {}
    msg = details.get("message", event.get("title", event.get("event_type", "detection")))
    structured = (f'[exonerve@57345 vm="{event.get("vm_id","unknown")}" '
                  f'type="{event.get("event_type","")}" '
                  f'score="{event.get("score",0)}" '
                  f'verdict="{event.get("verdict","")}"]')
    return f"<{pri}>1 {ts} {host} exonerve - - {structured} {msg}"


class SiemExporter:
    """Thread-safe multi-format exporter. Never raises into the caller."""

    FORMATS = ("cef", "ecs", "syslog")

    def __init__(self,
                 fmt: str = "ecs",
                 file_path: Optional[str] = None,
                 collector: Optional[str] = None,
                 protocol: str = "udp",
                 enabled: bool = True):
        """
        fmt        : one of cef | ecs | syslog
        file_path  : append rendered lines here (durable, always safe)
        collector  : "host:port" of a syslog/HEC collector (optional)
        protocol   : udp | tcp
        """
        if fmt not in self.FORMATS:
            raise ValueError(f"fmt must be one of {self.FORMATS}, got {fmt!r}")
        self.fmt = fmt
        self.file_path = file_path
        self.protocol = protocol.lower()
        self.enabled = enabled
        self._addr = None
        if collector:
            try:
                host, port = collector.rsplit(":", 1)
                self._addr = (host, int(port))
            except Exception:
                self._addr = None
        self._lock = threading.Lock()
        self.stats = {"emitted": 0, "file_errors": 0, "net_errors": 0, "dropped": 0}

    def render(self, event: Dict) -> str:
        if self.fmt == "cef":
            return to_cef(event)
        if self.fmt == "syslog":
            return to_syslog(event)
        return to_ecs_json(event)

    def emit(self, event: Dict) -> bool:
        """Render + ship one detection. Returns True if it landed anywhere."""
        if not self.enabled:
            return False
        try:
            line = self.render(event)
        except Exception:
            with self._lock:
                self.stats["dropped"] += 1
            return False

        landed = False
        if self.file_path:
            landed |= self._write_file(line)
        if self._addr:
            landed |= self._send_net(line)
        with self._lock:
            if landed:
                self.stats["emitted"] += 1
            else:
                self.stats["dropped"] += 1
        return landed

    def emit_many(self, events: List[Dict]) -> int:
        return sum(1 for e in events if self.emit(e))

    def _write_file(self, line: str) -> bool:
        try:
            directory = os.path.dirname(self.file_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with self._lock:
                with open(self.file_path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            return True
        except Exception:
            with self._lock:
                self.stats["file_errors"] += 1
            return False

    def _send_net(self, line: str) -> bool:
        payload = line.encode("utf-8", errors="replace")
        try:
            if self.protocol == "tcp":
                with socket.create_connection(self._addr, timeout=3.0) as s:
                    s.sendall(payload + b"\n")
            else:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.settimeout(3.0)
                    s.sendto(payload, self._addr)
            return True
        except Exception:
            with self._lock:
                self.stats["net_errors"] += 1
            return False


def exporter_from_env() -> Optional[SiemExporter]:
    """Build an exporter from environment, or None if SIEM export is off.

    EXONERVE_SIEM_FORMAT     cef | ecs | syslog      (default ecs)
    EXONERVE_SIEM_FILE       path to append to
    EXONERVE_SIEM_COLLECTOR  host:port
    EXONERVE_SIEM_PROTO      udp | tcp               (default udp)
    """
    fmt = os.environ.get("EXONERVE_SIEM_FORMAT", "ecs").lower()
    path = os.environ.get("EXONERVE_SIEM_FILE")
    collector = os.environ.get("EXONERVE_SIEM_COLLECTOR")
    proto = os.environ.get("EXONERVE_SIEM_PROTO", "udp")
    if not path and not collector:
        return None
    try:
        return SiemExporter(fmt=fmt, file_path=path, collector=collector, protocol=proto)
    except Exception:
        return None
