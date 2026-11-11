"""Tests for v1.1 upgrades: perimeter engines + self-healing subsystem."""
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "blue_team", "waf_engine"))
sys.path.insert(0, os.path.join(ROOT, "blue_team", "ids_engine"))
sys.path.insert(0, os.path.join(ROOT, "blue_team", "firewall"))


# ------------------------- WAF -------------------------
class TestWAF:
    def _waf(self):
        from waf_engine import WafEngine
        return WafEngine()

    def test_sqli_blocked(self):
        r = self._waf().inspect({"uri": "/p", "args": "id=1 OR 1=1--"})
        assert r["verdict"] == "BLOCK" and "T1190" in r["techniques"]

    def test_jndi_blocked(self):
        r = self._waf().inspect({"uri": "/", "headers": "UA: ${jndi:ldap://x/a}"})
        assert r["verdict"] == "BLOCK"

    def test_benign_allowed(self):
        r = self._waf().inspect({"uri": "/home", "args": "page=2",
                                 "headers": "User-Agent: Mozilla/5.0"})
        assert r["verdict"] == "ALLOW" and r["score"] == 0


# ------------------------- IDS/IPS -------------------------
class TestIDS:
    def test_known_bad_ip_drops_in_ips_mode(self):
        from ids_engine import IDSEngine
        f = IDSEngine(mode="ips").inspect(
            {"src_ip": "10.0.0.5", "dst_ip": "185.220.1.9", "dst_port": 443})
        assert any(x.rule == "SIG-BADIP" and x.verdict == "DROP" for x in f)

    def test_port_scan_detected(self):
        from ids_engine import IDSEngine
        eng = IDSEngine(mode="ids", scan_ports_threshold=15)
        out = []
        for p in range(20, 40):
            out = eng.inspect({"src_ip": "10.0.0.66", "dst_ip": "10.0.0.9",
                               "dst_port": p, "ts": time.time()})
        assert any(x.rule == "ANO-PORTSCAN" for x in out)

    def test_benign_no_finding(self):
        from ids_engine import IDSEngine
        f = IDSEngine(mode="ips").inspect(
            {"src_ip": "10.0.0.5", "dst_ip": "10.0.0.6", "dst_port": 443})
        assert f == []


# ------------------------- Firewall -------------------------
class TestFirewall:
    def _policy(self):
        from firewall import FirewallPolicy
        return FirewallPolicy.from_config([
            {"action": "deny", "dir": "out", "dst": "185.220.1.9/32", "note": "C2"},
            {"action": "allow", "dir": "in", "proto": "tcp", "port": 443},
        ], default_action="deny")

    def test_default_deny(self):
        r = self._policy().evaluate(
            {"dir": "in", "proto": "tcp", "src_ip": "1.2.3.4",
             "dst_ip": "10.0.0.9", "dst_port": 22})
        assert r["action"] == "deny" and r["matched"] is False

    def test_explicit_allow(self):
        r = self._policy().evaluate(
            {"dir": "in", "proto": "tcp", "src_ip": "1.2.3.4",
             "dst_ip": "10.0.0.9", "dst_port": 443})
        assert r["action"] == "allow"

    def test_enforce_is_dryrun(self):
        enf = self._policy().enforce_block(mgmt_allow="10.0.0.0/24")
        assert enf["enforced"] is True and enf["dry_run"] is True


# ------------------------- Self-healing -------------------------
class TestSelfHealing:
    def test_reflex_isolates_on_critical(self):
        from self_healing import SelfHealingRuntime
        isolated = []
        rt = SelfHealingRuntime(effectors={"containment": lambda c: isolated.append(c.entity),
                                           "healing": lambda c: None})
        rt.sense("sentry", "crypto_spike", "critical", "vm-1", techniques=["T1486"])
        assert isolated == ["vm-1"]

    def test_low_severity_no_reflex(self):
        from self_healing import SelfHealingRuntime
        isolated = []
        rt = SelfHealingRuntime(effectors={"containment": lambda c: isolated.append(c.entity)})
        rt.sense("ids", "network", "low", "vm-1")
        assert isolated == []

    def test_dead_component_triggers_heal(self):
        from self_healing import SelfHealingRuntime
        healed = []
        rt = SelfHealingRuntime(effectors={"healing": lambda c: healed.append(c.entity),
                                           "containment": lambda c: None,
                                           "failover": lambda c: None})
        rt.health.register("sentry_agent", interval=1.0)
        rt.heartbeat("sentry_agent", cpu_percent=10)
        rt.health.components["sentry_agent"].last_beat -= 10
        rt.tick()
        assert "sentry_agent" in healed

    def test_circuit_breaker_trips_and_recovers(self):
        from self_healing import CircuitBreaker
        cb = CircuitBreaker("x", fail_threshold=3, cooldown_s=0.0)
        for _ in range(3):
            cb.record_failure()
        assert cb.state.value == "open"
        assert cb.allow() is True          # cooldown 0 -> half-open
        cb.record_success()
        assert cb.state.value == "closed"

    def test_health_state_transitions(self):
        from self_healing import HealthMonitor
        hm = HealthMonitor()
        hm.register("c", interval=1.0)
        hm.heartbeat("c", cpu_percent=10)
        assert hm.components["c"].state.value == "healthy"
        hm.sweep(now=time.time() + 5)
        assert hm.components["c"].state.value == "dead"


# ------------------------- Robustness / hardening -------------------------
class TestRobustness:
    """Engines must never crash on malformed / empty / hostile input."""

    def test_waf_handles_empty_and_missing_fields(self):
        from waf_engine import WafEngine
        w = WafEngine()
        for bad in ({}, {"uri": None}, {"args": 12345}, {"headers": {"x": 1}},
                    {"uri": "", "args": "", "body": ""}):
            r = w.inspect(bad)
            assert r["verdict"] in ("ALLOW", "BLOCK")  # returns, never raises

    def test_ids_handles_missing_fields(self):
        from ids_engine import IDSEngine
        eng = IDSEngine(mode="ips")
        for bad in ({}, {"src_ip": None}, {"dst_port": "notaport"}, {"event": "auth_fail"}):
            out = eng.inspect(bad)
            assert isinstance(out, list)  # never raises

    def test_firewall_handles_bad_cidr_and_ports(self):
        from firewall import FirewallPolicy
        pol = FirewallPolicy.from_config([
            {"action": "allow", "dir": "in", "src": "not-a-cidr", "port": "bad"},
        ], default_action="deny")
        r = pol.evaluate({"dir": "in", "src_ip": "1.2.3.4", "dst_port": 443})
        assert r["action"] in ("allow", "deny")  # bad rule simply doesn't match

    def test_nervous_system_faulty_subscriber_does_not_kill_bus(self):
        from self_healing import NervousSystem, AfferentSignal, Severity, SignalKind
        ns = NervousSystem()
        ns.subscribe(SignalKind.AFFERENT, lambda s: 1 / 0)  # explodes
        ok = []
        ns.subscribe(SignalKind.AFFERENT, lambda s: ok.append(True))  # must still run
        ns.sense(AfferentSignal("t", "x", Severity.LOW, entity="e"))
        assert ok == [True]  # bus survived the faulty subscriber

    def test_healing_never_loops_forever(self):
        from self_healing import SelfHealingRuntime
        rt = SelfHealingRuntime(effectors={"healing": lambda c: None,
                                           "containment": lambda c: None,
                                           "failover": lambda c: None})
        rt.health.register("control_center", interval=1.0)
        rt.heartbeat("control_center", cpu_percent=10)
        rt.health.components["control_center"].last_beat -= 100
        for _ in range(50):          # hammer the loop
            rt.tick()
        # must have escalated to a human rather than thrashing infinitely
        assert len(rt.healer.escalations) >= 1


# ------------------------- Real libvirt backend (dry-run) -------------------------
class TestLibvirtBackend:
    def _be(self):
        import os, sys
        sys.path.insert(0, os.path.join(ROOT, "host_control_plane"))
        from libvirt_backend import build_libvirt_backend
        return build_libvirt_backend(dry_run=True)

    def test_dry_run_is_default_and_safe(self):
        be = self._be()
        assert be.dry_run is True and be.mode == "dry-run"
        r = be.isolate_vm("web-vm-01")
        assert r.success and r.operation == "isolate_vm"
        assert r.details["executed"] is False        # nothing executed

    def test_full_ir_sequence(self):
        be = self._be()
        ops = [r.operation for r in be.full_incident_response("web-vm-01")]
        assert ops == ["isolate_vm", "dump_memory", "snapshot", "revert"]

    def test_isolate_emits_real_virsh_command(self):
        be = self._be()
        r = be.isolate_vm("web-vm-01")
        assert "detach-interface web-vm-01" in r.details["command"]

    def test_failover_backend_is_interface_compatible(self):
        import os, sys
        sys.path.insert(0, os.path.join(ROOT, "host_control_plane"))
        from libvirt_backend import LibvirtFailoverBackend
        from failover_orchestrator import FailoverOrchestrator
        fob = LibvirtFailoverBackend(dry_run=True)
        # drop-in into the orchestrator and run a real-path failover (dry-run)
        orch = FailoverOrchestrator(backend=fob)
        orch.register_service("web-app", vip="10.0.0.100",
                              active_vm="vm-a", standby_vms=["vm-b"])
        res = orch.handle_compromise("vm-a")
        assert res["active_node"] == "vm-b"
        assert res["state"] in ("DEGRADED", "RESTORED", "HEALTHY")


# ------------------------- Security: YARA eval sandbox gate -------------------------
class TestYaraEvalGate:
    """The YARA condition evaluator must reject anything that isn't a boolean/
    numeric expression BEFORE eval() — closing the __subclasses__ escape path."""

    def _gate(self, cond):
        import re
        probe = re.sub(r"\b(?:True|False|and|or|not)\b", " ", cond)
        return bool(re.fullmatch(r"[\d\.\s()<>=!+\-*/%]*", probe))

    def test_allows_legitimate_boolean_and_numeric(self):
        for c in ["True and False", "(True or False) and not False",
                  "12345 < 1024", "2.5 > 1.0 and True"]:
            assert self._gate(c) is True

    def test_blocks_sandbox_escape_payloads(self):
        for c in ["().__class__.__bases__[0].__subclasses__()",
                  "__import__('os').system('id')",
                  "open('/etc/passwd')",
                  "().__class__"]:
            assert self._gate(c) is False

    def test_engines_use_no_eval_safe_parser(self):
        import os, re
        for mod in ("blue_team/yara_engine/yara_engine.py",
                    "blue_team/sigma_engine/sigma_engine.py"):
            src = open(os.path.join(ROOT, mod)).read()
            assert "safe_eval_bool" in src, mod + " should use safe_eval_bool"
            # no real eval() CALL on a condition/expression variable (ignore
            # string literals like a YARA signature and comments):
            for line in src.splitlines():
                code = line.split("#", 1)[0]
                if '"' in code or "'" in code:
                    continue  # skip lines containing string literals
                assert not re.search(r"(?<![\w.])eval\s*\(", code), mod + " calls eval(): " + line.strip()

    def test_safe_eval_blocks_escapes(self):
        import sys
        sys.path.insert(0, ROOT)
        from common.safe_eval import safe_eval_bool, SafeEvalError
        assert safe_eval_bool("True and not False") is True
        for payload in ["().__class__.__bases__[0].__subclasses__()",
                        "__import__('os').system('id')", "open('/etc/passwd')"]:
            try:
                safe_eval_bool(payload)
                assert False, "should have rejected"
            except SafeEvalError:
                pass

# ------------------------- Deterministic Decision Engine (non-AI) -------------------------
class TestDecisionEngine:
    def _eng(self):
        import sys
        sys.path.insert(0, ROOT)
        from decision_engine import DecisionEngine
        return DecisionEngine()

    def _fact(self, **kw):
        import sys
        sys.path.insert(0, ROOT)
        from decision_engine import Fact
        return Fact(**kw)

    def test_ransomware_hard_gate_contains(self):
        d = self._eng().decide(self._fact(event_type="crypto_spike", severity="critical",
                                          techniques=["T1486"]))
        assert d.verdict.value == "contain" and d.confidence == 1.0

    def test_irreversible_uncertain_escalates_to_human(self):
        d = self._eng().decide(self._fact(event_type="driver_load", severity="medium",
                                          reversible=False))
        assert d.verdict.value == "escalate" and d.escalated is True

    def test_high_sev_with_standby_prefers_failover(self):
        d = self._eng().decide(self._fact(event_type="network", severity="high",
                                          score=60, has_standby=True,
                                          asset_criticality="crown_jewel"))
        assert d.verdict.value == "failover"

    def test_low_severity_monitors(self):
        d = self._eng().decide(self._fact(event_type="heartbeat", severity="low"))
        assert d.verdict.value == "monitor"

    def test_deterministic_same_input_same_output(self):
        eng = self._eng()
        f = self._fact(event_type="lolbin", severity="medium", score=30)
        assert eng.decide(f).to_dict()["verdict"] == eng.decide(f).to_dict()["verdict"]

    def test_decision_is_explainable(self):
        d = self._eng().decide(self._fact(event_type="network", severity="high", score=60,
                                          has_standby=True))
        # every decision must expose the rules that produced it
        assert len(d.fired) >= 1 and all("rationale" in r for r in d.fired)
        assert "because" in d.explain()


# ------------------------- Kill-chain reconstructor -------------------------
class TestKillChain:
    def _kc(self):
        import sys, os
        sys.path.insert(0, os.path.join(ROOT, "blue_team", "killchain_reconstructor"))
        from killchain_reconstructor import KillChainReconstructor
        return KillChainReconstructor()

    def test_full_chain_reaches_impact(self):
        kc = self._kc().reconstruct(["T1595", "T1059.001", "T1003.001",
                                     "T1071", "T1567.002", "T1486"])
        assert kc.reached_impact is True and kc.completeness == 1.0

    def test_steps_ordered_by_tactic(self):
        kc = self._kc().reconstruct(["T1486", "T1595", "T1071"])  # out of order in
        orders = [s.order for s in kc.steps]
        assert orders == sorted(orders)  # output is ordered

    def test_early_stage_low_completeness(self):
        kc = self._kc().reconstruct(["T1595"])
        assert kc.reached_impact is False and kc.completeness < 0.2


# ------------------------- Decision engine wired into control plane -------------------------
class TestDecisionWiring:
    def _engine(self):
        import sys, os
        sys.path.insert(0, ROOT); sys.path.insert(0, os.path.join(ROOT, "host_control_plane"))
        from control_center import CorrelationEngine
        from hypervisor_api import HypervisorAPI, load_default_config
        from failover_orchestrator import FailoverOrchestrator, SimulatedBackend
        return CorrelationEngine(HypervisorAPI(load_default_config()),
                                 FailoverOrchestrator(SimulatedBackend(step_delay=0.0)))

    def test_critical_event_yields_contain_decision(self):
        e = self._engine()
        e.process_batch({"vm_id": "v1", "batch": [
            {"event_type": "crypto_spike", "severity": "critical", "details": {}}]})
        d = e.get_or_create_vm("v1").to_dict()["decision"]
        assert d["verdict"] == "contain" and d["action"] == "isolate_host"
        assert "explanation" in d and "because" in d["explanation"]

    def test_medium_event_yields_alert(self):
        e = self._engine()
        e.process_batch({"vm_id": "v2", "batch": [
            {"event_type": "lolbin", "severity": "medium", "details": {"binary": "rundll32.exe"}}]})
        assert e.get_or_create_vm("v2").to_dict()["decision"]["verdict"] == "alert"

    def test_every_vm_state_carries_an_explainable_decision(self):
        e = self._engine()
        e.process_batch({"vm_id": "v3", "batch": [
            {"event_type": "network", "severity": "low", "details": {}}]})
        d = e.get_or_create_vm("v3").to_dict()["decision"]
        assert d.get("fired") and all("rationale" in f for f in d["fired"])


# ------------------------- Blast-radius mapper -------------------------
class TestBlastRadius:
    def _mk(self):
        import sys, os
        sys.path.insert(0, os.path.join(ROOT, "blue_team", "blast_radius"))
        from blast_radius import BlastRadiusMapper, NetworkModel
        m = NetworkModel()
        m.add_asset("dmz", "normal"); m.add_asset("app", "normal")
        m.add_asset("db", "crown_jewel"); m.add_asset("island", "normal")
        m.add_edge("dmz", "app"); m.add_edge("app", "db")
        return BlastRadiusMapper(), m

    def test_reaches_crown_jewel(self):
        mapper, m = self._mk()
        br = mapper.compute(m, "dmz")
        assert "db" in br.reachable and br.most_critical == "db"

    def test_criticality_maps_for_decision_engine(self):
        mapper, m = self._mk()
        br = mapper.compute(m, "dmz")
        assert mapper.to_decision_criticality(br) == "crown_jewel"

    def test_isolated_asset_zero_radius(self):
        mapper, m = self._mk()
        br = mapper.compute(m, "island")
        assert br.score == 0.0 and not br.reachable


# ------------------------- No merge-conflict markers anywhere -------------------------
class TestNoConflictMarkers:
    def test_no_conflict_markers_in_any_repo_file(self):
        import os, re
        pat = re.compile(r'^(<{7}|={7}|>{7})( |$)')
        offenders = []
        for root, dirs, files in os.walk(ROOT):
            if ".git" in root:
                continue
            for fn in files:
                fp = os.path.join(root, fn)
                try:
                    with open(fp, encoding="utf-8", errors="ignore") as fh:
                        for i, line in enumerate(fh, 1):
                            if pat.match(line):
                                offenders.append(f"{fp}:{i}")
                except Exception:
                    pass
        assert not offenders, "merge-conflict markers found: " + ", ".join(offenders)

    def test_old_name_fully_removed(self):
        import os
        # the product name must be fully Exonerve in all code/config.
        # Build the search term from parts so THIS test file never contains it.
        needle = "van" + "guard"
        hits = []
        for root, dirs, files in os.walk(ROOT):
            if ".git" in root:
                continue
            for fn in files:
                if fn.endswith((".py", ".html", ".toml", ".cfg", ".service",
                                ".bat", ".sh", ".json", ".yml", ".yaml")):
                    fp = os.path.join(root, fn)
                    try:
                        if needle in open(fp, encoding="utf-8", errors="ignore").read().lower():
                            hits.append(fp)
                    except Exception:
                        pass
        assert not hits, "stale old-name references: " + ", ".join(hits)

    def test_no_old_ascii_banner(self):
        import os
        # the old name's banner had this exact box-character signature line
        sig = "\u255a\u2588\u2588\u2557 \u2588\u2588\u2554\u255d"  # start of the old V glyph row
        old_row = "\u255a\u2588\u2588\u2557 \u2588\u2588\u2554\u255d\u2588\u2588\u2554\u2550\u2550\u2588\u2588\u2551"
        hits = []
        for root, dirs, files in os.walk(ROOT):
            if ".git" in root: continue
            for fn in files:
                if fn.endswith((".py", ".sh")):
                    fp = os.path.join(root, fn)
                    try:
                        if old_row in open(fp, encoding="utf-8", errors="ignore").read():
                            hits.append(fp)
                    except Exception: pass
        assert not hits, "old ASCII banner still present in: " + ", ".join(hits)


# ------------- Isolation honesty: never claim containment that didn't happen -------------
class TestIsolationHonesty:
    def _engine(self, hv_succeeds):
        import sys, os
        sys.path.insert(0, os.path.join(ROOT, "host_control_plane"))
        import control_center as cc
        from hypervisor_api import HypervisorResult
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).isoformat()
        def res(op): return HypervisorResult(success=hv_succeeds, operation=op,
                                             vm_id="v", message="x", timestamp=ts)
        class HV:
            def full_incident_response(self, vm_id):
                return [res("isolate_network"), res("dump_memory"),
                        res("restore_snapshot"), res("boot_headless")]
        class FO:
            def handle_compromise(self, vm_id): return None
            def has_standby(self, v): return False
        return cc, cc.CorrelationEngine(hypervisor=HV(), failover=FO(), containment=None)

    def test_unenforced_isolation_is_labeled_honestly(self):
        cc, eng = self._engine(hv_succeeds=False)
        vm = eng.get_or_create_vm("v")
        eng._trigger_isolation("v", "test")
        vm.recalculate_score()
        # decision was made, but nothing actually contained the VM
        assert vm.isolated is True
        assert vm.isolation_enforced is False
        assert vm.status == "QUARANTINE_UNENFORCED"
        assert "DECISION ONLY" in vm.isolation_detail

    def test_enforced_isolation_reports_isolated(self):
        cc, eng = self._engine(hv_succeeds=True)
        vm = eng.get_or_create_vm("v")
        eng._trigger_isolation("v", "test")
        vm.recalculate_score()
        assert vm.isolated is True
        assert vm.isolation_enforced is True
        assert vm.status == "ISOLATED"


# ------------- XSS hardening: vm_id sanitized + dashboard escapes output -------------
class TestXSSHardening:
    def test_vm_id_sanitized_at_boundary(self):
        import sys, os
        sys.path.insert(0, os.path.join(ROOT, "host_control_plane"))
        import control_center as cc
        f = cc.CorrelationEngine._safe_vm_id
        assert f("test-vm-01") == "test-vm-01"          # normal preserved
        assert f("web-01.prod_2") == "web-01.prod_2"    # dots/underscores ok
        assert "<" not in f("<img src=x onerror=alert(1)>")  # markup stripped
        assert ">" not in f("<script>alert(1)</script>")
        assert f("") == "unknown"
        assert f(None) == "unknown"

    def test_dashboard_has_escape_helper_and_csp(self):
        import os
        html = open(os.path.join(ROOT, "host_control_plane", "dashboard.html"),
                    encoding="utf-8").read()
        assert "function esc(" in html, "dashboard must define an HTML-escape helper"
        # the risky fields must be escaped, not raw
        assert "${esc(a.title)}" in html
        assert "${esc(a.assignee)}" in html or "esc(a.assignee)" in html
        assert "${esc(vm.vm_id)}" in html

    def test_control_center_sets_csp_header(self):
        import os
        src = open(os.path.join(ROOT, "host_control_plane", "control_center.py"),
                   encoding="utf-8").read()
        assert "Content-Security-Policy" in src
        assert "X-Content-Type-Options" in src


# ------------- Official Sigma modifier support (community-rule compatibility) -------------
class TestSigmaModifiers:
    def _mv(self):
        import sys, os
        sys.path.insert(0, os.path.join(ROOT, "blue_team", "sigma_engine"))
        from sigma_engine import _match_value
        return _match_value

    def test_full_modifier_set(self):
        mv = self._mv()
        assert mv("powershell.exe", "power", "contains") is True
        assert mv("10.0.0.5", "10.0.0.0/24", "cidr") is True
        assert mv("192.168.1.5", "10.0.0.0/24", "cidr") is False
        assert mv(4444, 1024, "gt") is True
        assert mv(80, 1024, "gt") is False
        assert mv(22, "22", "lte") is True
        assert mv("program.exe", "PROGRAM.EXE", None) is True     # ci default
        assert mv("program.exe", "PROGRAM.EXE", "cased") is False  # case sensitive
        assert mv("nltest -dclist", "/dclist", "windash|contains") is True

    def test_base64_modifier(self):
        import base64
        mv = self._mv()
        data = "prefix" + base64.b64encode(b"whoami").decode() + "suffix"
        assert mv(data, "whoami", "base64") is True

    def test_community_loader_reports_compatibility(self):
        import sys, os, tempfile
        sys.path.insert(0, os.path.join(ROOT, "blue_team", "sigma_engine"))
        from sigma_engine import SigmaEngine
        d = tempfile.mkdtemp()
        sub = os.path.join(d, "windows", "process_creation")
        os.makedirs(sub)
        with open(os.path.join(sub, "r.yml"), "w") as fh:
            fh.write("title: T\nid: x\nlevel: high\n"
                     "detection:\n  selection:\n    Image|endswith: 'rundll32.exe'\n"
                     "  condition: selection\ntags: [attack.t1003.001]\n")
        eng = SigmaEngine()
        rep = eng.load_community_rules(d)
        assert rep["loaded"] == 1 and rep["scanned"] == 1
        hits = eng.evaluate({"Image": "C:/Windows/System32/rundll32.exe"})
        assert any(r.title == "T" for r in hits)


# ------------- Tamper-evident decision audit log (DFIR) -------------
class TestDecisionAuditLog:
    def _fresh(self):
        import tempfile, os
        from common.audit_log import DecisionAuditLog
        p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
        return p, DecisionAuditLog(p, key=b"k")

    def test_intact_chain_verifies(self):
        from common.audit_log import verify_file
        p, log = self._fresh()
        log.record("MONITOR", "v", "x", {"score": 10})
        log.record("CONTAIN", "v", "y", {"score": 115})
        r = verify_file(p, b"k")
        assert r["ok"] is True and r["entries"] == 2

    def test_edit_is_detected(self):
        import json
        from common.audit_log import verify_file
        p, log = self._fresh()
        log.record("MONITOR", "v", "x", {"score": 10})
        log.record("CONTAIN", "v", "y", {"score": 115})
        lines = open(p).read().splitlines()
        rec = json.loads(lines[1]); rec["data"]["score"] = 5
        lines[1] = json.dumps(rec); open(p, "w").write("\n".join(lines) + "\n")
        assert verify_file(p, b"k")["ok"] is False

    def test_deletion_is_detected(self):
        from common.audit_log import verify_file
        p, log = self._fresh()
        for v in ("MONITOR", "ALERT", "CONTAIN"):
            log.record(v, "v", "x", {})
        lines = open(p).read().splitlines()
        del lines[1]
        open(p, "w").write("\n".join(lines) + "\n")
        assert verify_file(p, b"k")["ok"] is False

    def test_wrong_key_is_detected(self):
        from common.audit_log import verify_file
        p, log = self._fresh()
        log.record("CONTAIN", "v", "x", {})
        assert verify_file(p, b"WRONG")["ok"] is False


# ------------- ATT&CK Navigator layer export -------------
class TestAttackNavigator:
    def test_coverage_layer_is_valid(self):
        import sys, os
        sys.path.insert(0, os.path.join(ROOT, "common"))
        from attack_navigator import coverage_layer
        layer = coverage_layer()
        # required Navigator layer fields
        for k in ("name", "versions", "domain", "techniques", "gradient"):
            assert k in layer
        assert layer["domain"] == "enterprise-attack"
        assert layer["versions"]["layer"] == "4.5"
        assert len(layer["techniques"]) > 0
        # every technique entry has the required shape
        for t in layer["techniques"]:
            assert "techniqueID" in t and "score" in t and t["enabled"] is True

    def test_live_layer_scores_by_count(self):
        import sys, os
        sys.path.insert(0, os.path.join(ROOT, "common"))
        from attack_navigator import live_layer
        layer = live_layer({"T1486": 3, "T1490": 1})
        scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
        assert scores.get("T1486") == 3
        assert layer["gradient"]["maxValue"] == 3

    def test_layer_serializes_to_json(self):
        import sys, os, json, tempfile
        sys.path.insert(0, os.path.join(ROOT, "common"))
        from attack_navigator import coverage_layer, write_layer
        p = os.path.join(tempfile.mkdtemp(), "layer.json")
        write_layer(coverage_layer(), p)
        reloaded = json.load(open(p))
        assert reloaded["versions"]["navigator"] == "4.9.1"


# ------------- Audit log hard-fails on corrupt tail (court-defensible) -------------
class TestAuditLogHardFail:
    def test_corrupt_tail_raises(self):
        import tempfile, os, pytest
        from common.audit_log import DecisionAuditLog, AuditIntegrityError
        p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
        log = DecisionAuditLog(p, key=b"k")
        log.record("CONTAIN", "v", "x", {})
        # corrupt the tail
        with open(p, "a") as fh:
            fh.write("{ this is not valid json\n")
        os.environ.pop("EXONERVE_AUDIT_ALLOW_RESET", None)
        with pytest.raises(AuditIntegrityError):
            DecisionAuditLog(p, key=b"k")   # must refuse to silently continue

    def test_override_allows_reset(self):
        import tempfile, os
        from common.audit_log import DecisionAuditLog
        p = os.path.join(tempfile.mkdtemp(), "a.jsonl")
        DecisionAuditLog(p, key=b"k").record("CONTAIN", "v", "x", {})
        with open(p, "a") as fh:
            fh.write("garbage\n")
        os.environ["EXONERVE_AUDIT_ALLOW_RESET"] = "1"
        try:
            DecisionAuditLog(p, key=b"k")   # allowed to start fresh
        finally:
            os.environ.pop("EXONERVE_AUDIT_ALLOW_RESET", None)


# ------------- STIX 2.1 export -------------
class TestStixExport:
    def test_bundle_is_valid_stix21(self):
        import sys, os
        sys.path.insert(0, os.path.join(ROOT, "common"))
        from stix_export import build_bundle
        b = build_bundle(sigma_ids={"T1486": "T1486_ransomware"})
        assert b["type"] == "bundle" and b["id"].startswith("bundle--")
        types = {}
        for o in b["objects"]:
            types[o["type"]] = types.get(o["type"], 0) + 1
            if o["type"] != "bundle":
                assert o.get("spec_version") == "2.1"
                assert "--" in o["id"]
        assert types.get("attack-pattern", 0) > 0
        assert types.get("indicator", 0) == types.get("attack-pattern", 0)
        assert types.get("relationship", 0) == types.get("attack-pattern", 0)

    def test_ids_are_deterministic(self):
        import sys, os
        sys.path.insert(0, os.path.join(ROOT, "common"))
        from stix_export import build_bundle
        a = build_bundle()
        b = build_bundle()
        ids_a = sorted(o["id"] for o in a["objects"])
        ids_b = sorted(o["id"] for o in b["objects"])
        assert ids_a == ids_b  # re-export yields stable ids


# ------------- Parser fuzzing (custom parsers must never crash/hang/mis-parse) -------------
class TestParserFuzzing:
    def test_safe_eval_and_sigma_survive_fuzzing(self):
        import sys
        sys.path.insert(0, ROOT)
        from tests.fuzz_parsers import run
        # bounded run for CI; the standalone tool does far more
        assert run(iterations=1500, seed=1337) is True


# ------------- Audit log path is cwd-independent (relative-path bug fix) -------------
class TestAuditPathAnchored:
    def test_default_path_is_absolute_and_stable(self):
        import os
        from common.audit_log import DecisionAuditLog
        cwd0 = os.getcwd()
        try:
            p1 = DecisionAuditLog().path
            os.chdir(os.path.join(ROOT, "host_control_plane"))
            p2 = DecisionAuditLog().path
            assert p1 == p2                      # same regardless of cwd
            assert os.path.isabs(str(p1))        # absolute
            assert "host_control_plane/host_control_plane" not in str(p1)  # no doubling
        finally:
            os.chdir(cwd0)


# ------------- CycloneDX SBOM -------------
class TestSBOM:
    def test_sbom_is_valid_cyclonedx(self):
        import sys, os
        sys.path.insert(0, os.path.join(ROOT, "common"))
        from sbom import build_sbom
        s = build_sbom()
        assert s["bomFormat"] == "CycloneDX"
        assert s["specVersion"] == "1.5"
        assert s["serialNumber"].startswith("urn:uuid:")
        assert s["metadata"]["component"]["name"] == "exonerve"
        assert len(s["components"]) >= 4          # flask, requests, psutil, cryptography, pyyaml
        for c in s["components"]:
            assert c["type"] == "library"
            assert c["purl"].startswith("pkg:pypi/")
            assert "name" in c
