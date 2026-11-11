#!/usr/bin/env python3
"""
Exonerve :: Kernel-Adjacent Telemetry  (v3.12 — "kernel visibility, honestly")
=================================================================================
The honest answer to "can this see what a kernel driver sees": not by writing
a custom kernel driver in this session. That needs a real kernel dev
environment (matching kernel headers, a target to load against, WDK +
driver-signing for Windows), months of stability testing, and a different
risk profile than user-mode Python code — shipping untested driver code is
exactly the kind of unverified claim this project has refused to make
anywhere else.

The honest, PRACTICAL path lightweight agents actually use: consume
telemetry from kernel-adjacent tools that are ALREADY signed, already
battle-tested, and already deployed in many real environments —

  - Linux:   auditd  (kernel audit subsystem, via /var/log/audit/audit.log)
  - Windows: Sysmon   (Microsoft Sysinternals, ETW-based, MS-signed)

This module does not run either of those — it PARSES their output into the
same normalized event shape the rest of this agent already understands
(pid, ppid, comm, exe, cmdline, uid, timestamp), so ProcessLineageMonitor-
style detectors can consume kernel-sourced events alongside psutil-sourced
ones. The concrete value this actually adds over psutil polling: catching
short-lived processes that spawn and exit BETWEEN poll ticks, which
psutil.process_iter() can miss entirely — auditd/Sysmon see every exec, not
a periodic snapshot.

HONESTY NOTE on verification: the parsers below are tested against
realistic, schema-accurate synthetic samples of both formats (both schemas
are stable, publicly documented, and haven't changed in years) — NOT
against a live auditd daemon or a live Sysmon install, because neither
exists in this sandbox. Before trusting this against real telemetry: point
it at a real audit.log / a real Sysmon EVTX export in an isolated test
environment and benchmark it there first, exactly the "prove it in
isolation before trusting it" step you already flagged as necessary.
"""
from __future__ import annotations

import re
# v3.13 security fix (bandit B314): stdlib xml.etree.ElementTree.fromstring()
# is vulnerable to XML entity-expansion DoS and, on some platforms/versions,
# external entity resolution. This module parses Sysmon XML from a source
# that — in a real deployment — could be compromised or spoofed, so this
# isn't a theoretical concern. defusedxml.ElementTree is a drop-in
# replacement with the same API, hardened against both. Falls back to the
# stdlib module (with a loud warning, not silently) only if defusedxml
# isn't installed, so this module still works without a hard new dependency
# — but the guest_production_vm requirements.txt now lists it as a real
# dependency, not an optional nicety, given what it protects against.
try:
    import defusedxml.ElementTree as ET
    _XML_HARDENED = True
except ImportError:  # pragma: no cover - exercised only if defusedxml is absent
    import warnings
    warnings.warn(
        "defusedxml is not installed — falling back to stdlib "
        "xml.etree.ElementTree, which is vulnerable to XML entity-expansion "
        "attacks. Install defusedxml (`pip install defusedxml`) before "
        "consuming Sysmon XML from any source you do not fully trust.",
        stacklevel=2)
    import xml.etree.ElementTree as ET
    _XML_HARDENED = False
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional


# ---------------------------------------------------------------------------
# Normalized event shape — what both parsers below produce, and what any
# consumer (this module or existing detectors) should read.
# ---------------------------------------------------------------------------

@dataclass
class KernelProcessEvent:
    source: str                    # "auditd" | "sysmon"
    pid: Optional[int]
    ppid: Optional[int]
    comm: Optional[str]            # short process name
    exe: Optional[str]             # full image path
    cmdline: Optional[str]         # full command line, if available
    uid: Optional[str]
    timestamp: Optional[str]       # ISO-ish, source-dependent precision
    paths: List[str] = field(default_factory=list)   # files this syscall touched
    raw: Dict = field(default_factory=dict)   # original fields, for audit trail


# ---------------------------------------------------------------------------
# Linux: auditd raw log parser
# ---------------------------------------------------------------------------
# Real auditd lines look like (fields vary by kernel/config, this covers the
# stable, universal ones):
#   type=SYSCALL msg=audit(1700000000.123:456): ... ppid=1234 pid=5678
#       uid=0 comm="bash" exe="/usr/bin/bash" ...
#   type=EXECVE msg=audit(1700000000.123:456): argc=3 a0="bash" a1="-c"
#       a2="curl evil.example"
# Multiple type=X lines sharing the same msg=audit(<ts>:<serial>) correlation
# key describe ONE exec event and must be joined before they're useful.

_AUDIT_HEADER_RE = re.compile(
    r'type=(?P<type>\S+)\s+msg=audit\((?P<ts>[\d.]+):(?P<serial>\d+)\):\s*(?P<rest>.*)')
# key="value with spaces" OR key=bareword — auditd quotes string fields,
# leaves numeric/hex fields bare.
_AUDIT_FIELD_RE = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')


@dataclass
class AuditRecord:
    type: str
    ts: str
    serial: str
    fields: Dict[str, str]


def parse_audit_line(line: str) -> Optional[AuditRecord]:
    """Parse ONE raw auditd log line. Returns None for lines that don't
    match the standard type=/msg=audit() header (blank lines, truncated
    lines, log rotation markers)."""
    m = _AUDIT_HEADER_RE.match(line.strip())
    if not m:
        return None
    fields: Dict[str, str] = {}
    for fm in _AUDIT_FIELD_RE.finditer(m.group("rest")):
        key = fm.group(1)
        val = fm.group(2) if fm.group(2) is not None else fm.group(3)
        fields[key] = val
    return AuditRecord(type=m.group("type"), ts=m.group("ts"),
                       serial=m.group("serial"), fields=fields)


def correlate_audit_records(records: Iterable[AuditRecord]) -> List[KernelProcessEvent]:
    """Group records sharing one (ts, serial) correlation key into one
    normalized process event. Only groups containing a SYSCALL record (the
    ones with pid/ppid/comm/exe) produce an event; a bare EXECVE or PATH
    record with no matching SYSCALL in the batch is dropped rather than
    guessed at."""
    groups: Dict[str, List[AuditRecord]] = {}
    for rec in records:
        groups.setdefault(f"{rec.ts}:{rec.serial}", []).append(rec)

    events: List[KernelProcessEvent] = []
    for key, group in groups.items():
        syscall = next((r for r in group if r.type == "SYSCALL"), None)
        if syscall is None:
            continue
        execve = next((r for r in group if r.type == "EXECVE"), None)
        cmdline = None
        if execve is not None:
            argc = int(execve.fields.get("argc", "0") or 0)
            parts = [execve.fields.get(f"a{i}", "") for i in range(argc)]
            cmdline = " ".join(p for p in parts if p)
        f = syscall.fields
        touched_paths = [r.fields["name"] for r in group
                        if r.type == "PATH" and "name" in r.fields]
        events.append(KernelProcessEvent(
            source="auditd",
            pid=_to_int(f.get("pid")), ppid=_to_int(f.get("ppid")),
            comm=f.get("comm"), exe=f.get("exe"), cmdline=cmdline,
            uid=f.get("uid"), timestamp=syscall.ts, paths=touched_paths,
            raw={r.type: r.fields for r in group},
        ))
    return events


def parse_audit_lines(lines: Iterable[str]) -> List[KernelProcessEvent]:
    """Convenience wrapper: parse a batch of raw lines (e.g. read from
    audit.log, or from `ausearch` output) straight into normalized events."""
    records = [r for r in (parse_audit_line(ln) for ln in lines) if r is not None]
    return correlate_audit_records(records)


def _to_int(s: Optional[str]) -> Optional[int]:
    try:
        return int(s) if s is not None else None
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Windows: Sysmon Event ID 1 (ProcessCreate) XML parser
# ---------------------------------------------------------------------------
# Schema is Microsoft's standard Windows Event Log XML, stable across Sysmon
# versions: https://learn.microsoft.com/sysinternals/downloads/sysmon
# (Event ID 1 fields: ProcessId, Image, CommandLine, ParentProcessId,
# ParentImage, ParentCommandLine, User, UtcTime)

_WINEVT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def parse_sysmon_process_create_xml(xml_text: str) -> Optional[KernelProcessEvent]:
    """Parse ONE Sysmon Event ID 1 (ProcessCreate) XML event. Returns None
    for a different event ID, or malformed XML — never raises into the
    caller, since a corrupt single event in a batch export must not abort
    parsing the rest."""
    try:
        # bandit flags this as B314 (unhardened XML parsing) — a false
        # positive as of this fix: `ET` is defusedxml.ElementTree in the
        # primary path (see the import block at the top of this module).
        # bandit does static pattern-matching on the call shape, not
        # branch-aware import resolution, so it can't tell the conditional
        # import already resolved this. The stdlib fallback path (only
        # reached if defusedxml is genuinely absent) warns loudly at import
        # time specifically because THAT path is the real residual risk.
        root = ET.fromstring(xml_text)  # nosec B314
    except ET.ParseError:
        return None

    # Namespaced (real Windows Event Log XML export) and un-namespaced
    # (many tools strip the default namespace when re-serializing) both
    # occur in practice — try namespaced first, fall back to bare tags.
    #
    # NOTE: `elem or fallback` is WRONG here and was a real bug caught by
    # tests/test_kernel_telemetry.py — ElementTree's Element.__bool__ is
    # based on whether it has CHILD elements, not on whether it was found.
    # A leaf element like <EventID>1</EventID> has no children, so a
    # successfully-found EventID element is falsy and `or` incorrectly
    # falls through to the fallback lookup. Must check `is not None`.
    event_id_el = root.find(".//e:EventID", _WINEVT_NS)
    if event_id_el is None:
        event_id_el = root.find(".//EventID")
    if event_id_el is None or (event_id_el.text or "").strip() != "1":
        return None

    data_els = root.findall(".//e:Data", _WINEVT_NS)
    if not data_els:
        data_els = root.findall(".//Data")
    data = {el.get("Name"): (el.text or "") for el in data_els if el.get("Name")}

    time_el = root.find(".//e:TimeCreated", _WINEVT_NS)
    if time_el is None:
        time_el = root.find(".//TimeCreated")
    timestamp = time_el.get("SystemTime") if time_el is not None else None

    return KernelProcessEvent(
        source="sysmon",
        pid=_to_int(data.get("ProcessId")),
        ppid=_to_int(data.get("ParentProcessId")),
        comm=(data.get("Image", "").split("\\")[-1] or None),
        exe=data.get("Image") or None,
        cmdline=data.get("CommandLine") or None,
        uid=data.get("User") or None,
        timestamp=timestamp,
        raw=data,
    )


def parse_sysmon_batch(xml_events: Iterable[str]) -> List[KernelProcessEvent]:
    """Parse a batch of individual <Event>...</Event> XML strings (e.g. one
    per line from a pre-split EVTX-to-XML export). Silently skips events
    that aren't ProcessCreate or that fail to parse — this is a filter over
    a mixed stream of Sysmon event types, not a strict-mode parser."""
    out = []
    for xml_text in xml_events:
        evt = parse_sysmon_process_create_xml(xml_text)
        if evt is not None:
            out.append(evt)
    return out


# ---------------------------------------------------------------------------
# Bridge into the existing process-lineage detection surface
# ---------------------------------------------------------------------------

def to_psutil_like(event: KernelProcessEvent) -> Dict:
    """Reshape a KernelProcessEvent into the same {pid, ppid, name, exe,
    cmdline, username} dict shape ProcessLineageMonitor and friends already
    consume from psutil, so kernel-sourced events can feed the SAME,
    already-tested detection logic rather than needing a parallel detector
    written from scratch for this source."""
    return {
        "pid": event.pid, "ppid": event.ppid, "name": event.comm,
        "exe": event.exe, "cmdline": event.cmdline.split() if event.cmdline else [],
        "username": event.uid, "_source": event.source, "_timestamp": event.timestamp,
    }
