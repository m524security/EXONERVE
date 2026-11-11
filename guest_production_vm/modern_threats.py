#!/usr/bin/env python3
"""
Exonerve :: Modern Threat Sensor Pack  (v3.9)
=================================================
Ransomware was never the whole picture. v3.8 closed the ransomware gaps; this
module covers the attack classes that dominate real 2024-2026 incidents and had
no coverage at all:

  Cloud          IMDS/SSRF credential theft, cloud credential-file harvesting
  Identity       infostealer access to browser credential/cookie stores
  Container      Docker socket abuse, K8s service-account token theft, escape
  Supply chain   package-manager postinstall spawning shells / network clients
  C2             command-and-control over legitimate SaaS (Discord/Telegram/
                 Slack/GitHub/Pastebin) and over tunnels (ngrok/cloudflared)
  Impact         cryptomining, destructive wipers
  Anti-forensics log truncation and shell-history destruction
  Access         reverse shells, SSH authorized_keys persistence

DESIGN RULE INHERITED FROM v3.8 — and it is the whole lesson of the last review:
    A detector only ships if a real sensor can produce its event. We do NOT add
    Sigma rules or ATT&CK mappings for techniques that nothing can emit. Every
    event type below is backed by code in this file.

SECOND RULE — every detector must have a benign analogue it deliberately
ignores, and that analogue must be covered by a test. A detector that only
proves it fires is half-tested.

Attribution is via psutil (process, open files, sockets). Where the platform
cannot give exact attribution, the event says so rather than implying certainty.
"""

from __future__ import annotations

import os
import re
import time
from collections import defaultdict, deque
from typing import Dict, Iterable, List, Optional, Set, Tuple

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None


# ---------------------------------------------------------------------------
# Cloud instance metadata (T1552.005)
# ---------------------------------------------------------------------------
# The link-local metadata endpoint hands out short-lived cloud role credentials
# to anything that can reach it. SSRF into this address is how a web-app bug
# becomes cloud account compromise (the Capital One pattern). On a healthy host
# only the cloud agent and provisioning tooling should ever talk to it.

IMDS_ENDPOINTS: Set[str] = {
    "169.254.169.254",     # AWS / Azure / GCP / OpenStack / DigitalOcean
    "169.254.170.2",       # AWS ECS task metadata
    "100.100.100.200",     # Alibaba Cloud
    "169.254.169.253",     # AWS route53 resolver (adjacent, worth noticing)
}

IMDS_EXPECTED_PROCESSES: Set[str] = {
    "cloud-init", "cloud-init-per", "amazon-ssm-agent", "ssm-agent",
    "aws", "awslogs", "amazon-cloudwatch-agent", "ecs-agent", "ecs-init",
    "google_metadata_script_runner", "google_guest_agent", "google_osconfig_agent",
    "waagent", "walinuxagent", "azure-vm-extension", "azuremonitoragent",
    "kubelet", "cloud-controller-manager", "systemd", "systemd-network",
    "chronyd", "ntpd", "dhclient", "networkmanager",
}

# Processes that have NO legitimate reason to read cloud role credentials.
# A web server or interpreter reaching IMDS is the SSRF signature.
IMDS_HIGH_RISK_PROCESSES: Set[str] = {
    "nginx", "apache2", "httpd", "php-fpm", "php", "node", "java", "tomcat",
    "python", "python3", "ruby", "perl", "curl", "wget", "bash", "sh", "dash",
    "powershell", "pwsh", "busybox", "nc", "ncat", "socat",
}


# ---------------------------------------------------------------------------
# Credential material on disk (T1552.001, T1555.003, T1552.007)
# ---------------------------------------------------------------------------

# Cloud / infra credential files. Path fragments, matched case-insensitively.
CLOUD_CRED_PATHS: Dict[str, str] = {
    "/.aws/credentials": "aws_credentials",
    "/.aws/config": "aws_config",
    "/.kube/config": "kubeconfig",
    "/.docker/config.json": "docker_registry_auth",
    "/.azure/accesstokens.json": "azure_tokens",
    "/.azure/azureprofile.json": "azure_profile",
    "/.config/gcloud/credentials.db": "gcloud_credentials",
    "/.config/gcloud/access_tokens.db": "gcloud_tokens",
    "/.ssh/id_rsa": "ssh_private_key",
    "/.ssh/id_ed25519": "ssh_private_key",
    "/.netrc": "netrc_credentials",
    "/.git-credentials": "git_credentials",
    "/.npmrc": "npm_token",
    "/.pypirc": "pypi_token",
    "/.terraform.d/credentials.tfrc.json": "terraform_cloud_token",
    "/var/run/secrets/kubernetes.io/serviceaccount/token": "k8s_service_account_token",
}

# Tools legitimately expected to read their own credential files.
CLOUD_CRED_EXPECTED: Dict[str, Set[str]] = {
    "aws_credentials": {"aws", "aws-cli", "python", "python3", "terraform", "packer",
                        "ansible", "boto3", "amazon-ssm-agent", "aws_completer"},
    "aws_config": {"aws", "aws-cli", "python", "python3", "terraform", "ansible"},
    "kubeconfig": {"kubectl", "helm", "k9s", "kubelet", "argocd", "flux", "terraform",
                   "lens", "kustomize", "skaffold"},
    "docker_registry_auth": {"docker", "dockerd", "containerd", "podman", "buildah",
                             "skopeo", "kaniko", "nerdctl"},
    "azure_tokens": {"az", "azure", "python", "python3", "terraform"},
    "azure_profile": {"az", "azure", "python", "python3", "terraform"},
    "gcloud_credentials": {"gcloud", "gsutil", "bq", "python", "python3", "terraform"},
    "gcloud_tokens": {"gcloud", "gsutil", "bq", "python", "python3", "terraform"},
    "ssh_private_key": {"ssh", "sshd", "scp", "sftp", "git", "ssh-agent", "ssh-add",
                        "rsync", "ansible", "mosh"},
    "netrc_credentials": {"curl", "git", "ftp", "wget", "python", "python3"},
    "git_credentials": {"git", "git-remote-https", "git-credential-store"},
    "npm_token": {"npm", "npx", "node", "yarn", "pnpm"},
    "pypi_token": {"pip", "pip3", "python", "python3", "twine", "poetry"},
    "terraform_cloud_token": {"terraform", "terragrunt"},
    "k8s_service_account_token": {"kubelet", "kube-proxy", "istio-agent", "envoy",
                                  "fluentd", "fluent-bit", "datadog-agent",
                                  "prometheus", "node-exporter", "filebeat"},
}

# Browser credential and session stores. Reading these is the core infostealer
# behaviour (Lumma, RedLine, Raccoon, Vidar) and the source of most stolen
# session cookies now driving AiTM account takeover.
BROWSER_CRED_ARTIFACTS: Tuple[str, ...] = (
    "login data", "cookies", "web data", "key4.db", "logins.json",
    "signons.sqlite", "cert9.db", "local state", "formhistory.sqlite",
    "places.sqlite",
)
# Real profile locations differ per-OS and per-browser, so these markers are
# written against the paths that actually exist on disk:
#   Linux   ~/.config/google-chrome/, ~/.mozilla/firefox/, ~/.config/chromium/
#   macOS   ~/Library/Application Support/Google/Chrome/
#   Windows AppData\Local\Google\Chrome\User Data\
# An earlier draft required a leading slash before the vendor name, which
# silently failed to match ~/.mozilla/firefox and ~/.config/google-chrome —
# i.e. it would have missed real Linux infostealers entirely.
BROWSER_PROFILE_MARKERS: Tuple[str, ...] = (
    "google-chrome", "google/chrome", "chromium", "mozilla/firefox",
    "microsoft/edge", "microsoft-edge", "bravesoftware", "brave-browser",
    "opera software", "opera stable", "vivaldi", "yandexbrowser",
    "google\\chrome", "mozilla\\firefox", "microsoft\\edge",
    "bravesoftware\\", "vivaldi\\",
)
BROWSER_PROCESSES: Set[str] = {
    "chrome", "chromium", "chrome.exe", "chromium.exe", "firefox", "firefox.exe",
    "brave", "brave.exe", "msedge", "msedge.exe", "edge", "opera", "opera.exe",
    "vivaldi", "vivaldi.exe", "safari", "crashpad_handler", "chrome_crashpad",
    # Backup and sync agents legitimately touch profile directories.
    "rsync", "restic", "borg", "duplicati", "timeshift", "deja-dup",
}


# ---------------------------------------------------------------------------
# Container escape / orchestration abuse (T1611, T1610, T1552.007)
# ---------------------------------------------------------------------------

CONTAINER_SOCKETS: Dict[str, str] = {
    "/var/run/docker.sock": "docker_socket",
    "/run/docker.sock": "docker_socket",
    "/var/run/containerd/containerd.sock": "containerd_socket",
    "/run/containerd/containerd.sock": "containerd_socket",
    "/var/run/crio/crio.sock": "crio_socket",
    "/run/podman/podman.sock": "podman_socket",
}
CONTAINER_SOCKET_EXPECTED: Set[str] = {
    "docker", "dockerd", "containerd", "containerd-shim", "podman", "crio",
    "kubelet", "compose", "docker-compose", "portainer", "watchtower",
    "buildkitd", "nerdctl", "ctr", "runc", "systemd",
}

# Host paths that should not be reachable from inside a container. Reading
# these from a containerised process indicates a hostPath mount or escape.
HOST_ESCAPE_PATHS: Tuple[str, ...] = (
    "/host/etc/shadow", "/host/root/", "/hostfs/", "/host-rootfs/",
    "/proc/sys/kernel/core_pattern", "/sys/kernel/uevent_helper",
    "/proc/1/root/", "/host/etc/kubernetes/",
)


def _lower(value: Optional[str]) -> str:
    return (value or "").lower()


def _xbasename(path: str) -> str:
    """Basename that works for BOTH separators regardless of host OS.

    os.path.basename() on Linux does not split Windows paths, so a telemetry
    path like C:\\Users\\a\\...\\Login Data would return the entire string and
    every filename comparison against it would silently fail. An agent must be
    able to reason about paths from the platform it is watching, not only the
    platform it happens to run on.
    """
    return re.split(r"[\\/]", path)[-1]


def _basename_noext(name: str) -> str:
    base = _xbasename(_lower(name))
    return base[:-4] if base.endswith(".exe") else base


def _proc_matches(proc_name: str, allowed: Iterable[str]) -> bool:
    """Allowlist match tolerant of versioned names (python3.11, node20)."""
    n = _basename_noext(proc_name)
    for a in allowed:
        if n == a or n.startswith(a):
            return True
    return False


class _Deduper:
    """Suppresses repeat emissions of an identical finding within a window."""

    def __init__(self, window: float = 300.0):
        self.window = window
        self._seen: Dict[str, float] = {}

    def should_emit(self, key: str) -> bool:
        now = time.time()
        # opportunistic prune so the map cannot grow unbounded
        if len(self._seen) > 4096:
            self._seen = {k: v for k, v in self._seen.items() if now - v < self.window}
        last = self._seen.get(key, 0.0)
        if now - last < self.window:
            return False
        self._seen[key] = now
        return True


# ---------------------------------------------------------------------------
# Detector: cloud metadata / IMDS credential theft  (T1552.005)
# ---------------------------------------------------------------------------

class CloudMetadataDetector:
    """Flags processes talking to the cloud instance-metadata endpoint.

    Severity is graded rather than flat: the cloud agent doing this is normal,
    a web server or interpreter doing it is the SSRF-to-cloud-credentials
    signature and is treated as critical.
    """

    def __init__(self, emit, dedupe_window: float = 300.0):
        self._emit = emit
        self._dedupe = _Deduper(dedupe_window)

    def scan(self) -> List[Dict]:
        if psutil is None:
            return []
        findings = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError, Exception):
            return []
        for conn in conns:
            if not conn.raddr or conn.raddr.ip not in IMDS_ENDPOINTS:
                continue
            if not conn.pid:
                continue
            try:
                proc = psutil.Process(conn.pid)
                name = _lower(proc.name())
                exe = _lower(proc.exe())
                cmdline = " ".join(proc.cmdline())[:256]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            if _proc_matches(name, IMDS_EXPECTED_PROCESSES):
                continue

            high_risk = _proc_matches(name, IMDS_HIGH_RISK_PROCESSES)
            if not self._dedupe.should_emit(f"imds:{name}:{conn.raddr.ip}"):
                continue

            detail = {
                "reason": "cloud_metadata_access",
                "endpoint": conn.raddr.ip,
                "process": name,
                "exe": exe[:256],
                "cmdline": cmdline,
                "pid": conn.pid,
                "high_risk_process": high_risk,
                "message": (
                    f"'{name}' contacted cloud metadata endpoint {conn.raddr.ip}"
                    + (" — web/interpreter process reaching IMDS is the SSRF "
                       "credential-theft signature" if high_risk else "")
                ),
            }
            self._emit("imds_access", "critical" if high_risk else "medium", detail)
            findings.append(detail)
        return findings


# ---------------------------------------------------------------------------
# Detector: credential material access  (T1552.001, T1552.007, T1555.003)
# ---------------------------------------------------------------------------

class CredentialAccessDetector:
    """Flags unexpected processes holding credential files open.

    Covers three distinct classes in one sweep because they share a mechanism:
      * cloud/infra credential files  -> T1552.001
      * Kubernetes service-account token -> T1552.007
      * browser credential + cookie stores -> T1555.003 / T1539 (infostealer)
    """

    def __init__(self, emit, dedupe_window: float = 300.0):
        self._emit = emit
        self._dedupe = _Deduper(dedupe_window)

    @staticmethod
    def _classify_cloud(path_l: str) -> Optional[str]:
        for fragment, label in CLOUD_CRED_PATHS.items():
            if fragment in path_l or fragment.replace("/", "\\") in path_l:
                return label
        return None

    @staticmethod
    def _is_browser_artifact(path_l: str) -> bool:
        if not any(m in path_l for m in BROWSER_PROFILE_MARKERS):
            return False
        base = _xbasename(path_l)
        return any(base == a or base.startswith(a) for a in BROWSER_CRED_ARTIFACTS)

    def scan(self) -> List[Dict]:
        if psutil is None:
            return []
        findings = []
        try:
            procs = list(psutil.process_iter(["pid", "name", "exe", "username"]))
        except Exception:
            return []

        for proc in procs:
            try:
                name = _lower(proc.info.get("name"))
                if not name:
                    continue
                open_files = proc.open_files()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue

            for f in open_files:
                path_l = _lower(f.path)

                label = self._classify_cloud(path_l)
                if label:
                    expected = CLOUD_CRED_EXPECTED.get(label, set())
                    if _proc_matches(name, expected):
                        continue
                    key = f"cred:{name}:{label}"
                    if not self._dedupe.should_emit(key):
                        continue
                    is_k8s = label == "k8s_service_account_token"
                    detail = {
                        "reason": "k8s_token_access" if is_k8s else "credential_file_access",
                        "credential_type": label,
                        "path": f.path[:256],
                        "process": name,
                        "pid": proc.info.get("pid"),
                        "user": proc.info.get("username"),
                        "message": (f"unexpected process '{name}' opened "
                                    f"{label.replace('_', ' ')} at {f.path}"),
                    }
                    self._emit("k8s_token_access" if is_k8s else "cred_file_access",
                               "critical", detail)
                    findings.append(detail)
                    continue

                if self._is_browser_artifact(path_l):
                    if _proc_matches(name, BROWSER_PROCESSES):
                        continue
                    key = f"browser:{name}:{_xbasename(path_l)}"
                    if not self._dedupe.should_emit(key):
                        continue
                    detail = {
                        "reason": "browser_credential_store_access",
                        "artifact": _xbasename(f.path),
                        "path": f.path[:256],
                        "process": name,
                        "pid": proc.info.get("pid"),
                        "user": proc.info.get("username"),
                        "message": (f"non-browser process '{name}' opened browser "
                                    f"credential/session store "
                                    f"'{_xbasename(f.path)}' — infostealer behaviour; "
                                    f"stolen session cookies enable MFA-bypassing account takeover"),
                    }
                    self._emit("browser_cred_theft", "critical", detail)
                    findings.append(detail)
        return findings


# ---------------------------------------------------------------------------
# Detector: container escape / runtime socket abuse  (T1611, T1610)
# ---------------------------------------------------------------------------

class ContainerEscapeDetector:
    """Flags container-runtime socket access and host-filesystem reach-through.

    Mounting /var/run/docker.sock into a container is the single most common
    container-escape path: anything holding it can start a privileged container
    with the host root filesystem mounted, which is a full host takeover.
    """

    def __init__(self, emit, dedupe_window: float = 300.0):
        self._emit = emit
        self._dedupe = _Deduper(dedupe_window)

    def scan(self) -> List[Dict]:
        if psutil is None:
            return []
        findings = []
        try:
            procs = list(psutil.process_iter(["pid", "name", "exe", "username"]))
        except Exception:
            return []

        for proc in procs:
            try:
                name = _lower(proc.info.get("name"))
                if not name:
                    continue
                open_files = proc.open_files()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                continue

            for f in open_files:
                path_l = _lower(f.path)

                sock_label = None
                for sock_path, label in CONTAINER_SOCKETS.items():
                    if path_l == sock_path or path_l.endswith(sock_path):
                        sock_label = label
                        break
                if sock_label and not _proc_matches(name, CONTAINER_SOCKET_EXPECTED):
                    if self._dedupe.should_emit(f"csock:{name}:{sock_label}"):
                        detail = {
                            "reason": "container_runtime_socket_access",
                            "socket": sock_label,
                            "path": f.path[:256],
                            "process": name,
                            "pid": proc.info.get("pid"),
                            "message": (f"unexpected process '{name}' holds {sock_label} — "
                                        f"container-runtime socket access grants host-level "
                                        f"control and is the primary escape path"),
                        }
                        self._emit("container_escape", "critical", detail)
                        findings.append(detail)
                    continue

                for esc in HOST_ESCAPE_PATHS:
                    if path_l.startswith(esc) or esc in path_l:
                        if self._dedupe.should_emit(f"cesc:{name}:{esc}"):
                            detail = {
                                "reason": "host_filesystem_reachthrough",
                                "host_path": f.path[:256],
                                "indicator": esc,
                                "process": name,
                                "pid": proc.info.get("pid"),
                                "message": (f"'{name}' accessed host path {f.path} — "
                                            f"hostPath mount or container escape"),
                            }
                            self._emit("container_escape", "critical", detail)
                            findings.append(detail)
                        break
        return findings


# ---------------------------------------------------------------------------
# Detector: software supply chain  (T1195.002)
# ---------------------------------------------------------------------------
# npm/pip/gem install scripts run arbitrary code as the installing user. A
# postinstall hook that spawns a shell or a network client is the standard
# malicious-package pattern, and it is how dependency-confusion and
# typosquatting payloads actually execute.

PACKAGE_MANAGERS: Set[str] = {
    "npm", "npx", "yarn", "pnpm", "pip", "pip3", "pipenv", "poetry", "uv",
    "gem", "bundle", "cargo", "go", "composer", "nuget", "dotnet", "mvn", "gradle",
}
SUPPLY_CHAIN_CHILDREN: Set[str] = {
    "sh", "bash", "dash", "zsh", "cmd", "cmd.exe", "powershell", "powershell.exe",
    "pwsh", "curl", "wget", "nc", "ncat", "netcat", "socat", "base64",
    "certutil", "bitsadmin", "mshta", "wscript", "cscript",
}
# Build steps legitimately invoke compilers and shells; these children are
# expected during native-module builds and must not fire.
SUPPLY_CHAIN_BENIGN_CHILDREN: Set[str] = {
    "node", "python", "python3", "make", "gmake", "cmake", "gcc", "g++", "cc",
    "clang", "ld", "ar", "node-gyp", "prebuild-install", "sccache", "rustc",
    "javac", "java", "git", "tar", "gzip", "unzip", "install",
}


class SupplyChainDetector:
    """Flags package managers spawning shells or network clients."""

    def __init__(self, emit, dedupe_window: float = 300.0):
        self._emit = emit
        self._dedupe = _Deduper(dedupe_window)

    def scan(self) -> List[Dict]:
        if psutil is None:
            return []
        findings = []
        try:
            procs = {p.pid: p for p in psutil.process_iter(
                ["pid", "name", "ppid", "cmdline", "username"])}
        except Exception:
            return []
        names = {pid: _basename_noext(p.info.get("name") or "")
                 for pid, p in procs.items()}

        for pid, proc in procs.items():
            try:
                child = names.get(pid, "")
                ppid = proc.info.get("ppid") or 0
                parent = names.get(ppid, "")
                if not child or not parent:
                    continue
                if parent not in PACKAGE_MANAGERS:
                    continue
                if child in SUPPLY_CHAIN_BENIGN_CHILDREN:
                    continue
                if child not in SUPPLY_CHAIN_CHILDREN:
                    continue
                cmdline = " ".join(proc.info.get("cmdline") or [])[:256]
                if not self._dedupe.should_emit(f"supply:{parent}:{child}"):
                    continue
                detail = {
                    "reason": "package_manager_spawned_payload",
                    "package_manager": parent,
                    "child_process": child,
                    "cmdline": cmdline,
                    "pid": pid,
                    "ppid": ppid,
                    "user": proc.info.get("username"),
                    "message": (f"package manager '{parent}' spawned '{child}' — "
                                f"malicious install-script behaviour "
                                f"(dependency confusion / typosquatting payload)"),
                }
                self._emit("supply_chain", "critical", detail)
                findings.append(detail)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings


# ---------------------------------------------------------------------------
# Detector: C2 over legitimate web services and tunnels  (T1102.002, T1572)
# ---------------------------------------------------------------------------
# Attackers increasingly run C2 through services every enterprise allows —
# Discord/Telegram/Slack webhooks, GitHub gists, Pastebin — because the TLS
# destination looks unremarkable. Detection here is intentionally narrow:
# a *non-browser, non-developer* process talking to these endpoints.

WEB_SERVICE_C2_HOSTS: Dict[str, str] = {
    "discord.com": "discord", "discordapp.com": "discord",
    "api.telegram.org": "telegram", "t.me": "telegram",
    "hooks.slack.com": "slack",
    "pastebin.com": "pastebin", "paste.ee": "paste_service",
    "gist.githubusercontent.com": "github_gist",
    "raw.githubusercontent.com": "github_raw",
    "api.github.com": "github_api",
    "transfer.sh": "file_transfer", "file.io": "file_transfer",
    "anonfiles.com": "file_transfer", "gofile.io": "file_transfer",
    "temp.sh": "file_transfer", "0x0.st": "file_transfer",
}
WEB_C2_ALLOWED_PROCESSES: Set[str] = BROWSER_PROCESSES | {
    "git", "git-remote-https", "gh", "code", "codium", "slack", "discord",
    "teams", "telegram", "telegram-desktop", "curl", "wget",
    "apt", "dnf", "yum", "snapd", "flatpak", "go", "cargo", "npm", "pip", "pip3",
}

TUNNEL_TOOLS: Set[str] = {
    "ngrok", "cloudflared", "chisel", "frpc", "frps", "gost", "iodine",
    "dnscat2", "ssf", "pagekite", "localtunnel", "lt", "bore", "tailscaled",
    "zerotier-one", "wstunnel", "revsocks", "ligolo", "ligolo-ng",
}
# Tunnels that are frequently sanctioned infrastructure rather than intrusion.
TUNNEL_OFTEN_SANCTIONED: Set[str] = {"cloudflared", "tailscaled", "zerotier-one"}

# ---------------------------------------------------------------------------
# Beacon-interval detector (v3.10, Priority 2.4)  — T1071
# ---------------------------------------------------------------------------
# EgressVolumeMonitor (ransomware_sensors.py) catches bulk transfers. Steady,
# low-volume beaconing over HTTPS moves no meaningful volume and is invisible
# to it. Regular, low-jitter connection TIMING to the same destination is a
# signal independent of volume — and it is derivable from connection
# timestamps the agent already samples via psutil.net_connections(), so this
# needs no new dependency and no packet capture.
BEACON_MIN_SAMPLES = 6          # need this many intervals to judge regularity
BEACON_MIN_INTERVAL_SECONDS = 10.0   # ignore chatter faster than this (keepalives,
                                      # HTTP/2 multiplexed bursts) — beaconing is
                                      # a periodic *reconnection* pattern, not a
                                      # busy long-lived session
BEACON_MAX_INTERVAL_SECONDS = 3600.0  # do not try to judge regularity across gaps
                                       # this large — too few samples in a
                                       # practical observation window either way
BEACON_JITTER_CV_THRESHOLD = 0.15     # coefficient of variation ceiling; human
                                       # browsing / normal app polling is far
                                       # jitterier than this
BEACON_ALLOWED_PROCESSES: Set[str] = WEB_C2_ALLOWED_PROCESSES | {
    "dropbox", "onedrive", "gdrive", "backblaze", "carbonite", "crashplan",
    "zoom", "outlook", "thunderbird", "steam", "spotify",
}


class WebServiceC2Detector:
    """Flags non-browser processes reaching SaaS endpoints commonly used for C2.

    LIMITATION, stated plainly: this resolves destinations by reverse DNS,
    which is slow, cacheable, and defeatable. It is a supporting signal, not a
    primary control. Direct-to-IP C2 will not be seen here.
    """

    def __init__(self, emit, dedupe_window: float = 600.0, resolver=None):
        self._emit = emit
        self._dedupe = _Deduper(dedupe_window)
        self._resolver = resolver          # injectable for tests
        self._rdns_cache: Dict[str, str] = {}

    def _rdns(self, ip: str) -> str:
        if self._resolver:
            return _lower(self._resolver(ip))
        if ip in self._rdns_cache:
            return self._rdns_cache[ip]
        try:
            import socket
            host = _lower(socket.gethostbyaddr(ip)[0])
        except Exception:
            host = ""
        if len(self._rdns_cache) > 2048:
            self._rdns_cache.clear()
        self._rdns_cache[ip] = host
        return host

    def scan(self) -> List[Dict]:
        if psutil is None:
            return []
        findings = []
        try:
            conns = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, PermissionError, Exception):
            return []
        for conn in conns:
            if conn.status != "ESTABLISHED" or not conn.raddr or not conn.pid:
                continue
            try:
                proc = psutil.Process(conn.pid)
                name = _lower(proc.name())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if _proc_matches(name, WEB_C2_ALLOWED_PROCESSES):
                continue
            host = self._rdns(conn.raddr.ip)
            if not host:
                continue
            service = None
            for domain, label in WEB_SERVICE_C2_HOSTS.items():
                if host.endswith(domain) or domain in host:
                    service = label
                    break
            if not service:
                continue
            if not self._dedupe.should_emit(f"webc2:{name}:{service}"):
                continue
            detail = {
                "reason": "c2_over_web_service",
                "service": service,
                "resolved_host": host,
                "dest_ip": conn.raddr.ip,
                "dest_port": conn.raddr.port,
                "process": name,
                "pid": conn.pid,
                "detection_confidence": "supporting",
                "message": (f"non-browser process '{name}' is talking to {service} "
                            f"({host}) — legitimate-SaaS C2 channel"),
            }
            self._emit("web_service_c2", "high", detail)
            findings.append(detail)
        return findings


class TunnelDetector:
    """Flags reverse-tunnel / ingress-exposure tooling running on the host."""

    def __init__(self, emit, dedupe_window: float = 600.0):
        self._emit = emit
        self._dedupe = _Deduper(dedupe_window)

    def scan(self) -> List[Dict]:
        if psutil is None:
            return []
        findings = []
        try:
            procs = list(psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]))
        except Exception:
            return []
        for proc in procs:
            try:
                name = _basename_noext(proc.info.get("name") or "")
                if name not in TUNNEL_TOOLS:
                    continue
                cmdline = " ".join(proc.info.get("cmdline") or [])[:256]
                if not self._dedupe.should_emit(f"tunnel:{name}"):
                    continue
                sanctioned = name in TUNNEL_OFTEN_SANCTIONED
                detail = {
                    "reason": "reverse_tunnel_tool",
                    "tool": name,
                    "cmdline": cmdline,
                    "pid": proc.info.get("pid"),
                    "user": proc.info.get("username"),
                    "commonly_sanctioned": sanctioned,
                    "message": (f"tunnelling tool '{name}' running — exposes internal "
                                f"services outbound and bypasses perimeter controls"
                                + (" (often sanctioned infrastructure; verify against "
                                   "your allowlist)" if sanctioned else "")),
                }
                self._emit("tunnel", "medium" if sanctioned else "high", detail)
                findings.append(detail)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings


class BeaconDetector:
    """Flags regular, low-jitter connection timing to one destination.

    HONEST LIMITATION, stated plainly (same posture as WebServiceC2Detector):
    this is a TIMING signal only. It does not inspect payload or volume, so
    it complements EgressVolumeMonitor rather than replacing it — a bulk
    transfer that happens once is still EgressVolumeMonitor's job; a small,
    recurring, clockwork-regular check-in is this detector's job. A jittered
    beacon (real malware increasingly adds random sleep skew specifically to
    defeat this class of detector) will not trip the coefficient-of-variation
    threshold; that gap is named in DEFENSE_GUIDE.md, not hidden.
    """

    def __init__(self, emit, dedupe_window: float = 600.0,
                 min_samples: int = BEACON_MIN_SAMPLES,
                 min_interval: float = BEACON_MIN_INTERVAL_SECONDS,
                 max_interval: float = BEACON_MAX_INTERVAL_SECONDS,
                 cv_threshold: float = BEACON_JITTER_CV_THRESHOLD,
                 history: int = 64):
        self._emit = emit
        self._dedupe = _Deduper(dedupe_window)
        self._min_samples = min_samples
        self._min_interval = min_interval
        self._max_interval = max_interval
        self._cv_threshold = cv_threshold
        self._sightings: Dict[str, deque] = defaultdict(lambda: deque(maxlen=history))

    def record_sighting(self, key: str, ts: Optional[float] = None) -> None:
        """Record one observed connection to `key` (e.g. "proc->ip:port").

        Exposed directly (not only via `scan()`) so it can be fed from a
        synthetic timeline in tests, and so any other poller with connection
        timestamps (e.g. SocketMonitor) can feed the same detector.
        """
        ts = ts if ts is not None else time.time()
        dq = self._sightings[key]
        if dq and ts == dq[-1]:
            return   # duplicate sighting within the same poll tick
        dq.append(ts)

    def _regularity(self, timestamps: Iterable[float]) -> Optional[Tuple[float, float]]:
        ts = list(timestamps)
        if len(ts) < self._min_samples + 1:
            return None
        intervals = [b - a for a, b in zip(ts, ts[1:])]
        if any(i < self._min_interval or i > self._max_interval for i in intervals):
            return None
        mean = sum(intervals) / len(intervals)
        if mean <= 0:
            return None
        variance = sum((i - mean) ** 2 for i in intervals) / len(intervals)
        cv = (variance ** 0.5) / mean
        return mean, cv

    def evaluate(self) -> List[Dict]:
        findings = []
        for key, dq in list(self._sightings.items()):
            reg = self._regularity(dq)
            if reg is None:
                continue
            mean, cv = reg
            if cv > self._cv_threshold:
                continue
            if not self._dedupe.should_emit(f"beacon:{key}"):
                continue
            detail = {
                "reason": "regular_interval_beaconing",
                "destination": key,
                "sample_count": len(dq),
                "mean_interval_seconds": round(mean, 2),
                "coefficient_of_variation": round(cv, 4),
                "detection_confidence": "supporting",
                "message": (f"connections to {key} recur roughly every "
                            f"{mean:.0f}s with low jitter (cv={cv:.3f}) — "
                            f"consistent with C2 beaconing independent of "
                            f"transferred volume"),
            }
            self._emit("beacon", "high", detail)
            findings.append(detail)
        return findings

    def scan(self) -> List[Dict]:
        if psutil is None:
            return []
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception:
            return []
        now = time.time()
        for conn in conns:
            if conn.status != "ESTABLISHED" or not conn.raddr or not conn.pid:
                continue
            try:
                proc = psutil.Process(conn.pid)
                name = _lower(proc.name())
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            if _proc_matches(name, BEACON_ALLOWED_PROCESSES):
                continue
            key = f"{name}->{conn.raddr.ip}:{conn.raddr.port}"
            self.record_sighting(key, now)
        return self.evaluate()


# ---------------------------------------------------------------------------
# Detector: cryptomining  (T1496)
# ---------------------------------------------------------------------------

MINER_PROCESS_NAMES: Set[str] = {
    "xmrig", "minerd", "cpuminer", "ccminer", "ethminer", "nbminer", "t-rex",
    "phoenixminer", "lolminer", "teamredminer", "gminer", "nanominer",
    "xmr-stak", "cgminer", "bfgminer", "kryptex", "srbminer",
}
MINING_POOL_PORTS: Set[int] = {3333, 4444, 5555, 7777, 8888, 9999, 14444, 45700}
MINING_POOL_KEYWORDS: Tuple[str, ...] = (
    "pool", "xmr", "monero", "nicehash", "minexmr", "supportxmr", "hashvault",
    "ethermine", "f2pool", "antpool", "2miners", "herominers",
)


class CryptominerDetector:
    """Flags cryptomining by name, by pool-port behaviour, and by sustained CPU.

    Name matching alone is trivially evaded by renaming the binary, so the
    behavioural path (sustained high CPU + mining-pool port) fires independently
    of the process name.
    """

    def __init__(self, emit, cpu_threshold: float = 80.0,
                 sustained_samples: int = 3, dedupe_window: float = 600.0):
        self._emit = emit
        self.cpu_threshold = cpu_threshold
        self.sustained_samples = sustained_samples
        self._dedupe = _Deduper(dedupe_window)
        self._cpu_history: Dict[int, deque] = defaultdict(lambda: deque(maxlen=8))

    def scan(self) -> List[Dict]:
        if psutil is None:
            return []
        findings = []
        pool_pids: Dict[int, Dict] = {}
        try:
            for conn in psutil.net_connections(kind="inet"):
                if conn.status != "ESTABLISHED" or not conn.raddr or not conn.pid:
                    continue
                if conn.raddr.port in MINING_POOL_PORTS:
                    pool_pids[conn.pid] = {"ip": conn.raddr.ip, "port": conn.raddr.port}
        except (psutil.AccessDenied, PermissionError, Exception):
            pass

        try:
            procs = list(psutil.process_iter(["pid", "name", "exe", "cmdline", "username"]))
        except Exception:
            return []

        for proc in procs:
            try:
                pid = proc.info.get("pid")
                name = _basename_noext(proc.info.get("name") or "")
                cmdline = " ".join(proc.info.get("cmdline") or "")[:256]
                cpu = proc.cpu_percent(interval=None)
                self._cpu_history[pid].append(cpu)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            hist = self._cpu_history[pid]
            sustained = (len(hist) >= self.sustained_samples
                         and all(c >= self.cpu_threshold
                                 for c in list(hist)[-self.sustained_samples:]))
            known_name = name in MINER_PROCESS_NAMES
            pool_conn = pool_pids.get(pid)
            cmd_l = _lower(cmdline)
            pool_hint = any(k in cmd_l for k in MINING_POOL_KEYWORDS)

            evidence, confidence = [], None
            if known_name:
                evidence.append("known_miner_binary")
                confidence = "high"
            if pool_conn:
                evidence.append(f"mining_pool_port_{pool_conn['port']}")
                confidence = "high"
            if pool_hint:
                evidence.append("pool_keyword_in_cmdline")
                confidence = confidence or "medium"
            if sustained:
                evidence.append(f"sustained_cpu_ge_{int(self.cpu_threshold)}pct")

            # Require a mining-specific indicator; sustained CPU alone is a
            # build server, not a miner.
            if not (known_name or pool_conn or pool_hint):
                continue
            if len(evidence) < 2 and not known_name:
                continue
            if not self._dedupe.should_emit(f"miner:{pid}:{name}"):
                continue

            detail = {
                "reason": "cryptomining_activity",
                "process": name,
                "pid": pid,
                "cmdline": cmdline,
                "evidence": evidence,
                "confidence": confidence or "medium",
                "sustained_cpu": sustained,
                "pool_connection": pool_conn,
                "message": (f"cryptomining indicators for '{name}': "
                            f"{', '.join(evidence)}"),
            }
            self._emit("cryptominer", "high", detail)
            findings.append(detail)
        return findings


# ---------------------------------------------------------------------------
# Detector: destructive wipe  (T1485)
# ---------------------------------------------------------------------------

class DataDestructionDetector:
    """Flags mass file deletion — the wiper pattern.

    Distinct from ransomware: a wiper destroys rather than encrypts, so no
    entropy transition ever occurs and the ransomware sensors stay silent.
    Fed by the filesystem monitor, which already tracks the file inventory.
    """

    def __init__(self, emit, window: int = 60, min_deletions: int = 100,
                 dedupe_window: float = 120.0):
        self._emit = emit
        self.window = window
        self.min_deletions = min_deletions
        self._deletions: deque = deque()
        self._dedupe = _Deduper(dedupe_window)

    def record_deletions(self, paths: Iterable[str]) -> None:
        now = time.time()
        for p in paths:
            self._deletions.append((now, p))

    def evaluate(self) -> Optional[Dict]:
        now = time.time()
        while self._deletions and self._deletions[0][0] < now - self.window:
            self._deletions.popleft()
        count = len(self._deletions)
        if count < self.min_deletions:
            return None
        if not self._dedupe.should_emit("wipe"):
            return None
        samples = [p for _, p in list(self._deletions)[:5]]
        detail = {
            "reason": "mass_file_deletion",
            "deleted_count": count,
            "window_seconds": self.window,
            "sample_paths": samples,
            "message": (f"{count} files deleted in {self.window}s — destructive "
                        f"wiper behaviour (no encryption, so entropy sensors "
                        f"will not fire)"),
        }
        self._emit("data_destruction", "critical", detail)
        return detail


# ---------------------------------------------------------------------------
# Detector: anti-forensics / log tampering  (T1070.002, T1070.003)
# ---------------------------------------------------------------------------

SENSITIVE_LOGS: Tuple[str, ...] = (
    "/var/log/auth.log", "/var/log/secure", "/var/log/syslog", "/var/log/messages",
    "/var/log/audit/audit.log", "/var/log/wtmp", "/var/log/btmp", "/var/log/lastlog",
    "/var/log/nginx/access.log", "/var/log/apache2/access.log",
)
HISTORY_FILES: Tuple[str, ...] = (
    ".bash_history", ".zsh_history", ".sh_history", ".python_history",
    ".mysql_history", ".psql_history", "consolehost_history.txt",
)
LOG_CLEAR_COMMANDS: Tuple[str, ...] = (
    "truncate -s 0", "wevtutil cl", "clear-eventlog", "journalctl --vacuum-time=1s",
    "history -c", "shred /var/log", "rm -rf /var/log", "> /var/log",
    "unset histfile", "export histsize=0", "set +o history",
)


class LogTamperDetector:
    """Flags log truncation and shell-history destruction.

    Two independent paths: shrink/removal observed on the filesystem, and
    known log-clearing commands observed in process command lines.
    """

    def __init__(self, emit, dedupe_window: float = 300.0):
        self._emit = emit
        self._dedupe = _Deduper(dedupe_window)
        self._log_sizes: Dict[str, int] = {}

    def check_filesystem(self) -> List[Dict]:
        findings = []
        for log_path in SENSITIVE_LOGS:
            try:
                size = os.path.getsize(log_path)
            except OSError:
                continue
            prev = self._log_sizes.get(log_path)
            self._log_sizes[log_path] = size
            # Logs are append-only in normal operation. Shrinkage means
            # truncation, which is either rotation or an attacker.
            if prev is not None and size < prev * 0.5 and prev > 4096:
                if not self._dedupe.should_emit(f"logtrunc:{log_path}"):
                    continue
                detail = {
                    "reason": "log_truncation",
                    "path": log_path,
                    "previous_size": prev,
                    "current_size": size,
                    "message": (f"{log_path} shrank {prev} -> {size} bytes — log "
                                f"truncation (verify against your rotation schedule)"),
                }
                self._emit("log_tamper", "high", detail)
                findings.append(detail)
        return findings

    def check_processes(self) -> List[Dict]:
        if psutil is None:
            return []
        findings = []
        try:
            procs = list(psutil.process_iter(["pid", "name", "cmdline", "username"]))
        except Exception:
            return []
        for proc in procs:
            try:
                cmdline = _lower(" ".join(proc.info.get("cmdline") or []))
                if not cmdline:
                    continue
                for pattern in LOG_CLEAR_COMMANDS:
                    if pattern in cmdline:
                        if not self._dedupe.should_emit(f"logcmd:{pattern}"):
                            break
                        detail = {
                            "reason": "log_clearing_command",
                            "pattern": pattern,
                            "cmdline": cmdline[:256],
                            "pid": proc.info.get("pid"),
                            "process": _lower(proc.info.get("name")),
                            "user": proc.info.get("username"),
                            "message": (f"log/history clearing command observed: "
                                        f"'{pattern}' — anti-forensics"),
                        }
                        self._emit("log_tamper", "high", detail)
                        findings.append(detail)
                        break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings

    def scan(self) -> List[Dict]:
        return self.check_filesystem() + self.check_processes()


# ---------------------------------------------------------------------------
# Detector: reverse shell  (T1059.004 / T1071)
# ---------------------------------------------------------------------------

class ReverseShellDetector:
    """Detects a shell whose stdio is bound to a network socket (Linux).

    This is the structural definition of a reverse shell rather than a
    signature, so it does not depend on matching a payload string. Linux-only:
    it reads /proc/<pid>/fd, which has no portable Windows equivalent here.
    """

    SHELLS: Set[str] = {"sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "busybox"}

    def __init__(self, emit, dedupe_window: float = 300.0, proc_root: str = "/proc"):
        self._emit = emit
        self._dedupe = _Deduper(dedupe_window)
        self.proc_root = proc_root

    def _stdio_sockets(self, pid: int) -> List[str]:
        """Return which of fd 0/1/2 point at a socket."""
        bound = []
        for fd in (0, 1, 2):
            try:
                target = os.readlink(os.path.join(self.proc_root, str(pid), "fd", str(fd)))
            except (OSError, PermissionError):
                continue
            if target.startswith("socket:"):
                bound.append(f"fd{fd}")
        return bound

    def scan(self) -> List[Dict]:
        if psutil is None or not os.path.isdir(self.proc_root):
            return []
        findings = []
        try:
            procs = list(psutil.process_iter(["pid", "name", "cmdline", "username", "ppid"]))
        except Exception:
            return []
        for proc in procs:
            try:
                name = _basename_noext(proc.info.get("name") or "")
                if name not in self.SHELLS:
                    continue
                pid = proc.info.get("pid")
                bound = self._stdio_sockets(pid)
                # stdin AND (stdout or stderr) on a socket = interactive shell
                # over the network. A single redirected fd is common in normal
                # pipelines and would be noisy.
                if "fd0" not in bound or len(bound) < 2:
                    continue
                if not self._dedupe.should_emit(f"revshell:{pid}"):
                    continue
                detail = {
                    "reason": "shell_stdio_bound_to_socket",
                    "process": name,
                    "pid": pid,
                    "ppid": proc.info.get("ppid"),
                    "socket_bound_fds": bound,
                    "cmdline": " ".join(proc.info.get("cmdline") or [])[:256],
                    "user": proc.info.get("username"),
                    "message": (f"shell '{name}' (pid {pid}) has stdio bound to a "
                                f"network socket ({', '.join(bound)}) — reverse shell"),
                }
                self._emit("reverse_shell", "critical", detail)
                findings.append(detail)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return findings


# ---------------------------------------------------------------------------
# Detector: SSH authorized_keys persistence  (T1098.004)
# ---------------------------------------------------------------------------

class SSHPersistenceDetector:
    """Watches authorized_keys files for added keys.

    Appending a key to authorized_keys is durable, survives password rotation
    and MFA, and is one of the quietest persistence mechanisms on Linux.
    """

    def __init__(self, emit, key_paths: Optional[List[str]] = None,
                 dedupe_window: float = 300.0):
        self._emit = emit
        self._dedupe = _Deduper(dedupe_window)
        self._paths = key_paths or self._discover_paths()
        self._fingerprints: Dict[str, Set[str]] = {}
        self._primed = False

    @staticmethod
    def _discover_paths() -> List[str]:
        paths = ["/root/.ssh/authorized_keys", "/root/.ssh/authorized_keys2"]
        home_root = "/home"
        try:
            for user in os.listdir(home_root):
                paths.append(os.path.join(home_root, user, ".ssh", "authorized_keys"))
        except OSError:
            pass
        return paths

    @staticmethod
    def _read_keys(path: str) -> Set[str]:
        keys = set()
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        keys.add(parts[1][:64])      # the key blob prefix
                    else:
                        keys.add(line[:64])
        except OSError:
            return set()
        return keys

    def scan(self) -> List[Dict]:
        findings = []
        for path in self._paths:
            current = self._read_keys(path)
            if not current and path not in self._fingerprints:
                continue
            prev = self._fingerprints.get(path)
            self._fingerprints[path] = current
            if prev is None:
                continue                      # first sight = baseline, not a finding
            added = current - prev
            if not added:
                continue
            if not self._dedupe.should_emit(f"sshkey:{path}"):
                continue
            detail = {
                "reason": "authorized_keys_modified",
                "path": path,
                "keys_added": len(added),
                "key_prefixes": [k[:24] + "..." for k in list(added)[:3]],
                "total_keys": len(current),
                "message": (f"{len(added)} SSH key(s) added to {path} — persistence "
                            f"that survives password rotation and MFA"),
            }
            self._emit("ssh_persistence", "critical", detail)
            findings.append(detail)
        self._primed = True
        return findings


# ---------------------------------------------------------------------------
# Aggregate runner
# ---------------------------------------------------------------------------

class ModernThreatSuite:
    """Runs every modern-threat detector on one cadence.

    Sensors here are heavier than the ransomware pack (they enumerate open
    files and sockets across all PIDs), so the agent runs this on a slower
    interval than the filesystem walk.
    """

    def __init__(self, emit, enable_reverse_shell: bool = True):
        self.emit = emit
        self.imds = CloudMetadataDetector(emit)
        self.credentials = CredentialAccessDetector(emit)
        self.container = ContainerEscapeDetector(emit)
        self.supply_chain = SupplyChainDetector(emit)
        self.web_c2 = WebServiceC2Detector(emit)
        self.tunnels = TunnelDetector(emit)
        self.beacon = BeaconDetector(emit)
        self.miners = CryptominerDetector(emit)
        self.destruction = DataDestructionDetector(emit)
        self.log_tamper = LogTamperDetector(emit)
        self.ssh = SSHPersistenceDetector(emit)
        self.reverse_shell = ReverseShellDetector(emit) if enable_reverse_shell else None

    def scan_all(self) -> Dict[str, int]:
        """Run every detector. One failing sensor must never stop the others."""
        results: Dict[str, int] = {}
        detectors = [
            ("imds", self.imds), ("credentials", self.credentials),
            ("container", self.container), ("supply_chain", self.supply_chain),
            ("web_c2", self.web_c2), ("tunnels", self.tunnels),
            ("beacon", self.beacon),
            ("miners", self.miners), ("log_tamper", self.log_tamper),
            ("ssh", self.ssh),
        ]
        if self.reverse_shell:
            detectors.append(("reverse_shell", self.reverse_shell))
        for label, det in detectors:
            try:
                results[label] = len(det.scan() or [])
            except Exception:
                results[label] = -1        # sensor error, not a clean zero
        try:
            self.destruction.evaluate()
        except Exception:
            pass
        return results
