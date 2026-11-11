# Exonerve — Defence Guide & Known Evasions

**Version 3.13.0** · Companion to `README.md`

This document exists because a detection project that does not publish its own
bypass paths has not finished thinking. Every detector below is listed with
what it actually observes, how an attacker defeats it, and whether we accept
that risk or plan to close it.

Nothing here is theoretical hand-waving: each "what it observes" line
corresponds to code you can read, and each evasion is one we believe works.

---

## Table of contents

1. [How to read this](#how-to-read-this)
2. [Detector-by-detector evasion analysis](#detector-by-detector)
3. [Architectural evasions](#architectural-evasions)
4. [What Exonerve does not attempt to detect](#out-of-scope)
5. [Defence-in-depth recommendations](#defence-in-depth)
6. [Open items — roadmap](#open-items)

---

<a id="how-to-read-this"></a>
## 1. How to read this

| Field | Meaning |
|---|---|
| **Observes** | The concrete signal in code. Not the marketing description. |
| **Evasion** | A technique we believe defeats the detector today. |
| **Cost to attacker** | How much the evasion slows or constrains them. |
| **Status** | `ACCEPTED` (known, tolerated) · `MITIGATED` (partly covered elsewhere) · `PLANNED` (on the roadmap) |

A detector with a cheap evasion and `ACCEPTED` status is not a bug — it is a
documented limit. The layered design assumes individual detectors will be
bypassed; the goal is that bypassing *all* of them simultaneously is expensive.

---

<a id="detector-by-detector"></a>
## 2. Detector-by-detector evasion analysis

### 2.1 Crypto-spike / entropy transition — T1486
**File:** `guest_production_vm/ransomware_sensors.py` (`EntropyTransitionTracker`),
`sentry_agent.py` (`CryptographicSpikeDetector`, `file_entropy`)

**Observes:** Shannon entropy of a representative sample of each changed *or
newly created* file, and specifically the **transition** from a
plaintext-band prior (≤6.5 bits) to a ciphertext-band value (≥7.2 bits).
Fires on ≥3σ deviation from the host's own learned baseline rate.

**v3.10 change:** sampling is no longer head-only. Files comfortably larger
than one sample chunk are now sampled at head, middle, *and* tail, and the
highest of the three entropies is used (`file_entropy`, Priority 2.2). This
closes the specific bypass this table used to list as the single most
effective evasion: encrypting only the interior or only the tail of a file
to keep a head-only check in the plaintext band.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Encrypt strictly between the three sampled windows** (fine-grained sparse/interspersed encryption that lands outside head, middle, and tail) | Medium-high — requires deliberately avoiding three specific regions, not just "encrypt part of the file" | `ACCEPTED` — three fixed points is not full-file coverage. Files are still functionally destroyed for the victim even under this evasion, which limits how much it actually helps the attacker; documented as a residual gap regardless. |
| **Head-only or tail-only or interior-only encryption** | Low, but no longer effective | `MITIGATED` (v3.10) — whichever region is touched is now sampled |
| **Encrypt below the sigma threshold** | Medium — slows the attack | `MITIGATED` by `SlowBurnDetector` (rate-independent cumulative count) |
| **Encrypt only already-high-entropy files** (.zip, .jpg) so no transition is observed | High — restricts the attacker to files that are often least business-critical, and leaves documents untouched | `ACCEPTED` |
| **Pre-seed the baseline** — run benign high-entropy writes for hours before detonating, raising the learned baseline so the real burst looks normal | High — requires long dwell and patience | `ACCEPTED`. Baseline persistence (v3.8) makes this *harder* to do quickly but also means a poisoned baseline survives restarts. Genuine trade-off. |
| **Encrypt outside the monitored `--target-dir`** | Low | `ACCEPTED` — configuration responsibility. Monitor every data path. |

### 2.2 Mass extension rename / novel-extension rate — T1486
**File:** `ransomware_sensors.py` (`ExtensionRenameDetector`)

**Observes:** TWO independent signals as of v3.10:
1. **Clustering (original):** ≥12 newly-created files sharing one extension
   outside the `COMMON_EXT` allowlist, within 60 seconds.
2. **Novel-extension rate (v3.10, Priority 2.1):** ≥15 distinct
   *never-before-seen* extensions appearing within 60 seconds, AND those
   novel extensions making up ≥50% of all new non-common-extension files in
   that same window (the ratio gate — see below).

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Keep the original extension** — encrypt in place, never rename | Low. Many families already do this. | `ACCEPTED` — this detector is a *fast* signal, not a complete one. The entropy transition detector (§2.1) covers in-place encryption. |
| **Use a common extension** (`.tmp`, `.dat`, `.bak`) for encrypted output | Low | `ACCEPTED` — deliberate trade-off. Adding these to the watch set would generate constant false positives. |
| **Randomise the extension per file, uniquely** so no single extension reaches 12 and every extension is high-novelty-ratio | Low, but no longer effective on its own | `MITIGATED` (v3.10) — this is now exactly what the novel-rate signal is tuned for: near-1.0 novelty ratio, well above the 15-distinct / 50%-ratio bar for any attack encrypting more than a couple dozen files. |
| **Medium-cardinality extension randomisation** — cycle through a small-to-moderate pool (roughly 8-14) of random extensions, reusing each just under the fast-window thresholds, in a SINGLE wave | Medium — requires tuning pool size against two published thresholds | `MITIGATED` (v3.13). Closed differently than originally planned: population-entropy alone was tested against the FP corpus and found NOT to cleanly separate this attack from the legitimate multi-language build scenario (both can show similar per-window entropy at realistic scale) — an entropy-only fix would have risked a false sense of closure without reliably working. What actually closes it: a longer (24h) accumulation window on the SAME "is this extension novel" check, with a higher count threshold and no ratio requirement — a legitimate host's genuinely-new-extension count converges to a small number even at high file volume, while repeated introduction of fresh extension pools (needed to encrypt more than ~150 files from one pool under the fast clustering cap) accumulates past the long-window threshold. See `ExtensionRenameDetector._evaluate_long_window_novelty`. |
| **Same evasion, but the attacker throttles pool introduction to stay under the LONG-window threshold too** | High — now requires spreading the attack across days, not minutes, a real and meaningful cost given ransomware's core value is speed before detection | `ACCEPTED` — the residual gap after the v3.13 fix, stated plainly rather than implying full closure. An attacker patient enough to introduce new extension pools slowly over multiple days specifically to stay under 20 long-window-novel extensions would still evade both extension-based signals. The independent entropy-TRANSITION detector (§2.1) still runs on every file's actual content regardless of extension strategy, so this evasion only fully succeeds against an attacker who ALSO evades content-entropy detection (§2.1's own residual sparse-encryption gap) — a compound, harder-to-achieve evasion, named explicitly rather than left implicit. |
| **Rename slower than both thresholds allow** | Medium | `MITIGATED` by `SlowBurnDetector` |

**How the ratio gate works, and why it exists:** an earlier draft of the
novel-rate signal used only an absolute distinct-extension count. The v3.10
false-positive corpus (`tests/corpus/`, scenario `build_server`) found that
this alone false-positives on a large multi-language CI build, which
legitimately produces 15+ distinct output extensions (`.o`, `.obj`, `.rlib`,
`.class`, `.wasm`, …) the first time it runs. The fix requires novel
extensions to also be a *majority* of that window's new files — a build's
novel extensions are a handful of types spread across thousands of files
(low ratio); ransomware giving every file a unique extension is close to 1
novel extension per novel file (ratio near 1.0). See
`ExtensionRenameDetector._evaluate_novel_rate` and `FP_CORPUS_RESULTS.md`.

### 2.3 Bulk egress / exfiltration — T1567.002
**File:** `ransomware_sensors.py` (`EgressVolumeMonitor`)

**Observes:** **Measured outbound byte volume** from
`psutil.net_io_counters().bytes_sent`, over a 5-minute rolling window, against
a configurable threshold (default 500 MB). Process names are supporting
context only — they are never required to fire.

> **Explicit correction to prior documentation:** earlier versions listed
> T1567.002 with no live emitter at all; the event only existed because
> `attack_replay.py` injected it. It is now sensor-backed. See
> §"Real vs Simulated" in the README.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Low-and-slow exfil** — stay under 500 MB / 5 min (e.g. 50 MB/hour) | High for large datasets: 630 GB at 50 MB/hour takes over a year. Low for targeted theft of a small, high-value dataset. | `ACCEPTED` for small datasets. Tune `--egress-threshold-mb` down for sensitive hosts; the correct value is workload-specific. |
| **Blend with legitimate bulk traffic** on a host that already ships large volumes (backup server, CDN origin, media host) | Low on such hosts | `ACCEPTED` — do not deploy volume thresholds naively on high-egress hosts. Baseline first. |
| **Exfil from a host not running the agent** | Low | `ACCEPTED` — coverage responsibility. |
| **Renaming the transfer binary** (`rclone` → `svchost`) | **None — does not work.** Volume is the signal. | `MITIGATED` by design |
| **Attribution confusion** — run exfil from an allowlisted process name | Medium. The *volume alert still fires*; only the named candidate process is wrong. | `ACCEPTED` and disclosed: every event carries `attribution: correlational`. |

**Honest limitation:** per-PID network byte accounting is not portable through
`psutil` — the kernel exposes counters per interface, not per process, on our
target platforms. The byte volume is measured truth; the named process is the
leading candidate, not proof. An analyst is told this in the event itself.

### 2.4 Slow-burn encryption — T1486
**File:** `ransomware_sensors.py` (`SlowBurnDetector`)

**Observes:** Cumulative count of confirmed plaintext→ciphertext transitions
over a 1-hour window (default ≥150). Rate-independent by design.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Encrypt under 150 files/hour** | Very high — encrypting 100,000 files takes ~28 days of continuous dwell | `ACCEPTED` — this is the intended cost imposition |
| **Restart the host to clear the window** | Medium | `MITIGATED` — transitions persist across restarts (v3.8) |
| Anything that defeats §2.1's transition logic also defeats this | — | Inherited |

### 2.5 ESXi / hypervisor datastore encryption — T1486
**File:** `ransomware_sensors.py` (`EsxiEncryptionDetector`)

**Observes:** ≥3 files with VM-disk extensions (`.vmdk`, `.vmx`, `.vswp`,
`.qcow2`, `.vhdx`, …) showing a suspicious entropy transition within 60 s.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Encrypt VM disks in place at the block layer**, bypassing the file layer | Low if the attacker has hypervisor shell | `ACCEPTED` — a file-layer sensor cannot see block-layer writes. Real ESXi coverage needs a hypervisor-side agent. |
| **Encrypt fewer than 3 VM artifacts** | High — limits blast radius, defeating the purpose | `ACCEPTED` |
| **Rename VM disks before encrypting** | Low | **KNOWN GAP** — we match on extension. `PLANNED`: content-based VMDK header detection. |

### 2.6 Backup / shadow-copy destruction — T1490
**File:** `sentry_agent.py` (`ProcessLineageMonitor`), `SHADOW_COMMANDS` /
`UNIX_BACKUP_DESTRUCTION`

**Observes:** Process command lines containing known backup-destruction
strings (`vssadmin delete shadows`, `wbadmin delete catalog`, `zfs destroy`,
`btrfs subvolume delete`, `shred`, …).

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Call the Windows VSS COM API directly** (`IVssBackupComponents`) instead of spawning `vssadmin.exe` | Low for a competent developer — and increasingly common | `ACCEPTED` — **evaluated explicitly in v3.10 (Priority 2.3) and left as a named limitation, not simulated.** Direct COM calls never produce a command line to match; closing this for real requires a kernel-level ETW subscription to the VSS provider, which is out of scope for the current user-mode polling architecture (a fundamentally different privilege and platform-integration model, not an incremental change to this detector). No partial-coverage heuristic has been added in its place — see the OPEN items section. |
| **Obfuscate the command line** (env vars, escaped chars, `vss^admin`) | Very low | `ACCEPTED` — we do not normalise command lines |
| **Delete backups from a different host** (backup server, cloud console) | Low | `ACCEPTED` — out of host scope |
| **Use a renamed copy of `vssadmin.exe`** | Very low | `ACCEPTED` — we match the command string, not the binary hash |

> This detector is high-value when it fires (it is genuinely
> *left-of-encryption*) but it is **not** a reliable barrier. Treat it as an
> opportunistic early warning, not a control.

### 2.7 Agent tamper / heartbeat silence — T1562.001
**File:** `sentry_agent.py` (`HeartbeatEmitter`), `control_center.py` watchdog

**Observes:** Absence of an authenticated heartbeat past 3× the interval.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Replay captured heartbeats** to fake liveness | High — heartbeats are AES-256-GCM sealed with a per-agent key, carry a monotonic sequence, and the controller enforces a replay window | `MITIGATED` by design |
| **Suspend rather than kill the agent** (SIGSTOP) | Low to execute, but produces the same silence | `MITIGATED` — silence is silence; the alert fires either way |
| **Steal the agent key** from the guest and forge clean heartbeats | High — requires key extraction, but the key *is* on the box | `ACCEPTED` — **real limitation.** A fully-compromised guest can forge telemetry. This is why response runs out-of-band and why scoring is server-side; but a forged "all clear" is possible with sufficient access. |
| **Firewall the controller** so telemetry silently drops | Low | `MITIGATED` — blocked egress produces silence, which is itself the detection |

### 2.8 Suspicious process lineage / exec path
**File:** `sentry_agent.py` (`ProcessLineageMonitor`)

**Observes:** Web-server processes spawning shells; executables running from
`/tmp`, `/dev/shm`, `\AppData\Local\Temp`, etc.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Execute from a non-suspicious path** (`/usr/local/bin`, user home) | Very low | `ACCEPTED` — path heuristics are a tripwire, not a control |
| **In-memory execution** — never touch disk | Medium | `ACCEPTED` — no memory-resident detection in the agent |
| **Reparent** away from the web server (double-fork, systemd-run) | Low | `ACCEPTED` — we read `ppid` at poll time and lose the original parent |
| **Win the polling race** — finish within the 2 s poll interval | Medium | `ACCEPTED` — polling, not eventing. See §3.1. |

### 2.9 Unexpected outbound connection
**File:** `sentry_agent.py` (`SocketMonitor`)

**Observes:** ESTABLISHED outbound connections to ports outside {80, 443, 53,
123} from non-browser, non-system processes.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **C2 over 443** | Reduced for REGULAR-interval beaconing (see §2.22); unchanged (**none**) for aperiodic/jittered beaconing | Split as of v3.10: `EgressVolumeMonitor` covers the *bulk transfer* case; `BeaconDetector` (§2.22, Priority 2.4) now covers *regular-interval* low-volume beaconing over 443. Irregular, human-timed-looking, or deliberately jittered low-volume traffic over 443 remains `ACCEPTED` as undetected — no signal here distinguishes it from ordinary browsing. |
| **DNS tunnelling over 53** | None | `ACCEPTED` — `blue_team/dns_analyzer` covers this offline, but the live agent does not |
| **Masquerade as a browser process name** | Very low | `ACCEPTED` — name-based allowlist |

### 2.10 Cloud metadata credential theft — T1552.005
**File:** `modern_threats.py` (`CloudMetadataDetector`)

**Observes:** Established connections to link-local metadata IPs
(169.254.169.254, 169.254.170.2, 100.100.100.200) from a process outside the
cloud-agent allowlist. Severity is raised to critical when the process is a web
server or interpreter, which is the SSRF signature.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Rename the process to an allowlisted name** (`cloud-init`, `kubelet`) | Very low | `ACCEPTED` — allowlist is name-based |
| **Steal credentials once, use them off-host** | Low. One short connection may fall between polls. | `ACCEPTED` — polling, see §3.1 |
| **IMDSv2 session-token flow** | None — still a connection to the same endpoint | `MITIGATED` |
| **Reach IMDS from a different host** in the VPC | Low | `ACCEPTED` — host-scope sensor |

### 2.11 Credential-file access — T1552.001 / T1552.007
**File:** `modern_threats.py` (`CredentialAccessDetector`)

**Observes:** Processes holding credential files open (`~/.aws/credentials`,
kubeconfig, docker auth, SSH private keys, npm/PyPI tokens, K8s SA token) when
the process is not on that credential's expected-consumer allowlist.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Rename the binary to an allowlisted consumer** (`aws`, `kubectl`, `python3`) | Very low | `ACCEPTED` — **the primary bypass.** The allowlist is name-based and `python3` is on it, which is broad by necessity |
| **Read and close between polls** | Low — file reads are brief and `open_files()` is a point-in-time sample | `ACCEPTED` — a significant practical limitation; this detector catches sustained handles far more reliably than quick reads |
| **Read via a memory-mapped region or raw disk** | High | `ACCEPTED` |
| **Copy the file first, read the copy** | Low — the copy path is not watched | `ACCEPTED` |

### 2.12 Browser credential / cookie theft — T1555.003, T1539
**File:** `modern_threats.py` (`CredentialAccessDetector._is_browser_artifact`)

**Observes:** Non-browser processes opening browser password stores and cookie
databases across Linux, macOS and Windows profile layouts.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Masquerade as the browser** (`chrome`, `firefox`) | Very low | `ACCEPTED` |
| **Copy the whole profile directory, exfiltrate, parse elsewhere** | Low. The copy tool may be an allowlisted backup binary. | `ACCEPTED` — real infostealers already do this |
| **Read cookies from browser memory** rather than the DB | Medium | `ACCEPTED` — no memory inspection |
| **Use the browser's own remote-debugging port** to dump cookies | Medium | **KNOWN GAP** — no file is touched. `PLANNED`: watch for local connections to debug ports (9222). |

### 2.13 Container escape — T1611
**File:** `modern_threats.py` (`ContainerEscapeDetector`)

**Observes:** Non-runtime processes holding `docker.sock` / `containerd.sock` /
`crio.sock` / `podman.sock`, and access to host reach-through paths.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Escape via a privileged container without touching the socket** (kernel exploit, `/proc/self/exe` CVE-2019-5736, release_agent) | Medium-high | `ACCEPTED` — only the `core_pattern` and `release_agent` paths are watched |
| **Rename to a runtime-allowlisted name** | Very low | `ACCEPTED` |
| **hostPath mount at a path not on the watchlist** | Low — the list is finite | `ACCEPTED`; the list covers the common conventions only |
| **CI runners with legitimately mounted docker.sock** | n/a | Documented false positive — allowlist your runners |

### 2.14 Software supply chain — T1195.002
**File:** `modern_threats.py` (`SupplyChainDetector`)

**Observes:** A package manager process whose child is a shell or network
client, excluding the compiler/build children native modules legitimately spawn.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Execute the payload inside the interpreter** (pure-Python/JS payload, no child process) | Low — and common | `ACCEPTED` — **major gap.** In-process payloads spawn nothing |
| **Delay execution until after install** (first import, cron) | Low | `ACCEPTED` — the parent is no longer the package manager |
| **Spawn an allowlisted child** (`node`, `python`) that then acts | Low | `ACCEPTED` — build children must be allowlisted or every `npm install` alerts |
| **Reparent to escape the package-manager parent** | Low | `ACCEPTED` — see §2.8 |

### 2.15 C2 over legitimate web services — T1102.002
**File:** `modern_threats.py` (`WebServiceC2Detector`)

**Observes:** Non-browser processes with established connections whose reverse
DNS matches Discord / Telegram / Slack / GitHub / paste / file-transfer hosts.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Connect by IP with no usable rDNS** | Very low | `ACCEPTED` — **evaluated explicitly in v3.10 (Priority 2.5) and left as a named limitation.** No viable host-only signal distinguishes one raw-IP HTTPS connection from another without packet-level TLS fingerprinting (e.g. JA3/JA4), which is out of this agent's current scope — it has no packet capture, only `psutil`-level connection metadata. This detector is explicitly labelled `detection_confidence: supporting` in the event for this reason, and no low-confidence heuristic has been substituted in its place; see the OPEN items section. |
| **Use a SaaS host not on the list** (Firebase, Notion, Telegram CDN, any CDN) | Very low — the list can never be complete | `ACCEPTED` |
| **Masquerade as an allowlisted process** (`curl`, `git`) | Very low — and those are allowlisted by necessity | `ACCEPTED` |
| **Domain-fronting behind a shared CDN** | Low | `ACCEPTED` |

> Treat this as enrichment for triage, not as a control. It exists to make an
> analyst look twice, not to stop an attacker.

### 2.16 Protocol tunnelling — T1572
**File:** `modern_threats.py` (`TunnelDetector`)

**Observes:** Process names matching known tunnelling tools.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Rename the binary** | **Very low — fully defeats this detector** | `ACCEPTED`. Name matching only. Stated plainly because the same objection was correctly raised about the old exfil detector |
| **Use SSH remote port forwarding** (`ssh -R`) instead of a dedicated tool | Very low | **KNOWN GAP** — `sshd`/`ssh` cannot be flagged without constant false positives |
| **Use a tunnel not on the list** | Low | `ACCEPTED` |

### 2.17 Cryptomining — T1496
**File:** `modern_threats.py` (`CryptominerDetector`)

**Observes:** Three independent signals — known miner binary names, established
connections to mining-pool ports, and sustained CPU. A mining-specific
indicator is **required**; sustained CPU alone never fires (that is a build
server).

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Rename the binary AND use a non-standard pool port** | Medium — defeats both name and port paths | `ACCEPTED` — sustained CPU alone is deliberately insufficient, so this evades |
| **Throttle CPU** (mine at 30%) | Medium — proportionally less revenue | `MITIGATED` if a pool port or known name is still visible |
| **Proxy through a pool on 443** | Low | `ACCEPTED` |
| **Browser-based / WASM mining** | Low | `ACCEPTED` — the browser is allowlisted |

### 2.18 Destructive wipe — T1485
**File:** `modern_threats.py` (`DataDestructionDetector`)

**Observes:** ≥100 file deletions within 60 s, observed by inventory diff in the
filesystem monitor.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Delete slowly** (under 100 files/min) | High for a full wipe | `ACCEPTED` |
| **Overwrite in place instead of unlinking** | Low — the inventory never shrinks | **KNOWN GAP.** `PLANNED`: treat high-entropy overwrite with no rename as a wipe candidate |
| **Wipe outside `--target-dir`** | Low | `ACCEPTED` — configuration responsibility |
| **Destroy at the block layer / `mkfs`** | Low with root | `ACCEPTED` — file-layer sensor |
| **Large scheduled cleanup jobs** | n/a | Documented false positive |

### 2.19 Log and history tampering — T1070.002 / T1070.003
**File:** `modern_threats.py` (`LogTamperDetector`)

**Observes:** Sensitive log files shrinking by >50%, and known log-clearing
command strings.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Selective line removal** (`sed -i '/evil/d'`) — file barely shrinks | Very low | `ACCEPTED` — **the realistic bypass.** Surgical editing beats a size heuristic |
| **Obfuscate the clearing command** | Very low | `ACCEPTED` — string matching, see §2.6 |
| **Disable logging up front** rather than clearing after | Low | `ACCEPTED` |
| **Log rotation** | n/a | Documented false positive — verify against your rotation schedule |

### 2.20 Reverse shell — T1059.004
**File:** `modern_threats.py` (`ReverseShellDetector`)

**Observes:** A shell process with fd0 **and** fd1/fd2 pointing at sockets, read
from `/proc/<pid>/fd`. Structural, not signature-based, so payload obfuscation
does not help.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Non-shell implant** (Python/Go/C2 agent that never execs a shell) | Low — and standard for modern C2 | `ACCEPTED` — **the main bypass.** Only shell binaries are inspected |
| **Relay through a pty** so stdio points at `/dev/pts/N`, not a socket | Medium | `ACCEPTED` — pty-based reverse shells evade the structural test |
| **Short-lived shell between polls** | Medium | `ACCEPTED` — polling |
| **Windows** | n/a | **Not covered** — `/proc` has no portable Windows equivalent here |

### 2.21 SSH authorized_keys persistence — T1098.004
**File:** `modern_threats.py` (`SSHPersistenceDetector`)

**Observes:** New key entries appearing in watched `authorized_keys` files.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Persist somewhere else entirely** (systemd unit, cron, PAM, shell rc) | Low | `ACCEPTED` — only SSH keys are watched here |
| **Use a non-standard `AuthorizedKeysFile` path** from sshd_config | Low | **KNOWN GAP** — we do not parse sshd_config. `PLANNED` |
| **Add a key to a user home created after agent start** | Low | `ACCEPTED` — paths are enumerated once at construction |
| **Modify an existing key entry** rather than adding | Low | `ACCEPTED` — we compare key blobs, so a replaced blob does register as added |

### 2.22 Low-volume C2 beaconing — T1071
**File:** `modern_threats.py` (`BeaconDetector`) — new in v3.10, Priority 2.4

**Observes:** Connections to the same destination (`process->ip:port`)
recurring at a regular, low-jitter interval (coefficient of variation ≤
0.15) across at least 6 intervals, independent of transferred volume.
Complements `EgressVolumeMonitor` (§2.3), which only sees bulk transfers —
this detector's whole purpose is the low-volume case that leaves.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Add random sleep jitter to the beacon interval** | Low — this is a standard, cheap C2 framework feature (Cobalt Strike "jitter %", sliver, etc.) | `ACCEPTED` — **the primary bypass, stated plainly.** Real-world implants increasingly jitter specifically to defeat this class of detector; a CV above the 0.15 threshold evades entirely. |
| **Beacon faster than `BEACON_MIN_INTERVAL_SECONDS` (10s)** | Low, but increases volume/visibility elsewhere | `ACCEPTED` — deliberately excluded to avoid flagging legitimate keepalive/multiplexed traffic |
| **Beacon slower than `BEACON_MAX_INTERVAL_SECONDS` (1hr)** or vary destination each time | Medium — slows the attacker's tempo, or requires C2 infrastructure that rotates destinations | `ACCEPTED` — regularity can only be judged within a bounded observation window and against a stable destination |
| **Masquerade as an allowlisted process** (browser, sync client) | Very low | `ACCEPTED` — name-based allowlist, same trade-off as §2.9/§2.15 |
| **Route through a domain-fronted or CDN-shared destination that changes IP per connection** | Medium | `ACCEPTED` — the detector keys on destination IP:port; IP rotation breaks the "same destination" precondition |

**On the primary bypass above:** evaluated for a fix in v3.13 (a median-absolute-deviation-based regularity test was considered as more jitter-tolerant than coefficient-of-variation) and deliberately NOT shipped — a robustness improvement that hasn't been validated against real jittered C2 traffic samples risks producing a detector that merely *looks* more sophisticated without reliably closing the gap, which is its own kind of false confidence. Remains `ACCEPTED`, tracked in §6, rather than shipped half-validated.

### 2.23 Data exfiltration — access-then-egress graph — T1020
**File:** `guest_production_vm/exfil_detector.py` (`ExfilGraphDetector`) — new in v3.12

**Observes:** a process opening sensitive-looking files (credentials, backups,
customer/financial data — see `SENSITIVE_PATH_MARKERS`) followed by a
connection to a destination it hasn't talked to before, within
`ACCESS_TO_EGRESS_WINDOW_S` (120s default). A correlation signal,
independent of transfer volume.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Wait longer than the correlation window between access and egress** | Low — trivial to add a delay | `ACCEPTED` — a bounded correlation window is unavoidable; too wide a window would correlate unrelated activity and generate noise |
| **Exfiltrate to a destination already established as "known" for that process** (e.g. abuse an already-open, legitimate connection) | Medium — requires an existing channel to piggyback on | `ACCEPTED` — this detector specifically only fires on a NEW destination; reusing an established one is a real, named blind spot |
| **Give the sensitive file an innocuous-looking name** | Low | `ACCEPTED` — `SENSITIVE_PATH_MARKERS` is a keyword allowlist, the same allowlist trade-off as every other detector in this project |
| **Read the file via a path that never appears in `open_files()`** (e.g. memory-mapped access, or reading through a database engine that abstracts the file access away) | Medium-high | `ACCEPTED` — passive mode is polling-based (psutil); feeding `kernel_telemetry.py`-sourced events narrows this but does not close it for reads the kernel telemetry source itself doesn't surface either |

### 2.24 Honeytoken / canary files — T1005
**File:** `guest_production_vm/exfil_detector.py` (`HoneytokenManager`, `HoneytokenDetector`) — new in v3.12

**Observes:** any access to a planted decoy file, via kernel-sourced
telemetry (auditd/Sysmon). Near-zero-FP by construction.

| Evasion | Cost to attacker | Status |
|---|---|---|
| **Content-inspect before exfiltrating, notice the file is bait** | Was LOW until v3.13 | `MITIGATED` (v3.13) — **real gap found and fixed the same day it shipped.** The original content literally contained the text "DECOY FILE — planted by Exonerve," which a content-aware attacker (or automated exfil tooling that greps before grabbing) would spot instantly. Fixed: content is now plausible-looking with no self-identifying marker anywhere, verified by a dedicated regression test (`test_planted_content_never_self_identifies_as_bait`) that itself caught a SECOND instance of the same class of leak (the word "bait" survived into one fake-PEM string on the first fix attempt) before it shipped. |
| **The auditd/Sysmon watch rule was never actually installed on the planted path** | None — this is a deployment gap, not an evasion | `ACCEPTED`, named honestly rather than hidden: `HoneytokenManager.plant()` writes the files; `auditctl_watch_commands()` tells the operator exactly what to run, but does NOT run it — installing a live audit watch rule needs root and is a deliberate operational action. A honeytoken with no watch rule installed generates zero signal when touched, silently. |
| **Recognise the file by its filename pattern alone** (before any content read, e.g. from a directory listing) | Low-medium | `ACCEPTED` — `DEFAULT_LURE_NAMES` is a fixed, guessable list if an attacker has seen this project's source (which they can, it's open); operators should supply their own `lure_names` for real deployments rather than relying on the shipped defaults verbatim |

---

---

<a id="architectural-evasions"></a>
## 3. Architectural evasions

### 3.1 Polling → eventing (MITIGATED in v3.10, Priority 1.1)
**Status as of v3.9 and earlier:** the agent walked the target tree every
`--poll-interval` seconds (default 2 s) rather than subscribing to
filesystem events. Consequences: activity that started and finished inside
one interval could be missed entirely; detection latency was bounded below
by tree-walk duration, which grows with filesystem size; CPU cost scaled
with tree size, not with change rate.

**v3.10 fix:** `FilesystemMonitor` now defaults to event-driven watching
(`inotify` on Linux, `ReadDirectoryChangesW` on Windows, FSEvents on macOS,
all via the `watchdog` library) and falls back to the original polling walk
automatically — logged, never silent — if `watchdog` is not installed or the
underlying filesystem does not support recursive watches (some network
mounts, some container overlay filesystems). Both modes route through the
identical `_process_candidate` classification logic, so switching modes
changes *latency*, never *verdicts*. See `guest_production_vm/sentry_agent.py`
(`FilesystemMonitor`, `_WatchdogFSEventHandler`) and `tests/test_eventing.py`.

**Measured, not asserted** (`scripts/eventing_benchmark.py` — single-run,
single-machine sandbox measurement; re-run against representative hardware
for real capacity planning, see the script's own honesty note):

| Tree size | Mode | Avg CPU during idle+load window | RSS growth |
|---|---|---|---|
| 3,000 files | poll | 4.5% | ~1.8 MB |
| 3,000 files | event | 0.4% | ~60 KB |
| 8,000 files | poll | 11.2% | ~5.3 MB |
| 8,000 files | event | 0.6% | ~72 KB |

The expected shape holds: poll cost scales with tree size regardless of
whether anything changed; event cost stays roughly flat and tracks actual
change volume instead.

**Residual gaps, stated honestly rather than implying this is fully closed:**
- Filesystems without recursive-watch support (some network mounts, some
  container overlay filesystems) still fall back to polling, with the same
  latency characteristics as before on those specific mounts.
- A single burst larger than the per-tick drain cap (20,000 queued events)
  spills into the next tick rather than being dropped — bounded, not lost,
  but not instantaneous either at that scale.
- The Windows (`ReadDirectoryChangesW`) and macOS (FSEvents) backends are
  provided by `watchdog` and are not independently verified against a live
  Windows or macOS host in this round — this development and test
  environment is Linux-only. The poll-mode fallback path is unaffected
  either way if that backend misbehaves on a given host (see the automatic
  fallback behaviour above).

### 3.2 Compromised guest can forge telemetry
The agent's key lives on the monitored host. Root on the guest means the
ability to send authenticated-but-false telemetry. Mitigations in place:
server-side scoring (the agent cannot declare itself clean by inflating or
zeroing its own `score_delta` — the controller ignores agent-supplied deltas),
and out-of-band response. Not fully solvable with an in-guest agent.

### 3.3 Detection ≠ enforcement
When no hypervisor or root backend is available, containment displays
`QUARANTINE • UNENFORCED`. This is deliberate and honest, but operators must
read it: an unenforced quarantine stops nothing.

### 3.4 Dwell-time blindness
Exonerve detects the *detonation*, not the weeks of quiet recon, credential
theft, and lateral movement that precede real ransomware incidents. Nothing in
this repository addresses dwell. This is the gap that matters most in actual
incidents and it is honestly out of scope for a host sensor of this design.

### 3.5 On-call paging is now real, but is an alerting path, not a detection control
**v3.10 addition (Priority 1.2):** `common/ticketing_export.py` forwards
triage-worthy alerts (already deduped, already above `ALERT_MIN_DELTA` — see
`alert_manager.py`) to PagerDuty (Events API v2) and/or a generic webhook
(Opsgenie/ServiceNow/Jira/Slack-via-automation). This closes the "SIEM export
exists but nothing pages a human" gap.

What this does NOT change: it is a notification path layered on top of
detection, not a new detection capability, and it inherits every evasion
listed elsewhere in this document — a detector that never fires has nothing
to page on. Failure posture is the same as SIEM export and is tested
(`tests/test_ticketing_export.py`): a dead or slow ticketing endpoint is
caught, counted in `TicketingExporter.stats`, and never allowed to raise into
the detection/scoring/containment path.

---

<a id="out-of-scope"></a>
## 4. What Exonerve does not attempt to detect

Stated plainly so nobody assumes coverage that does not exist:

- Kernel-mode rootkits and hypervisor-level implants
- Firmware / UEFI persistence
- Block-layer encryption that bypasses the filesystem
- Encrypted C2 beaconing at low volume over standard ports, IF the beacon
  interval is irregular/jittered (regular-interval beaconing is now covered
  by `BeaconDetector`, §2.22, as of v3.10 — see that entry for its own
  jitter-evasion limitation)
- Insider threat with legitimate credentials and legitimate access patterns
- Supply-chain compromise of trusted software
- Anything on a host without the agent installed
- Windows reverse-shell detection (no portable `/proc/<pid>/fd` equivalent)
- In-process supply-chain payloads that never spawn a child
- Non-shell C2 implants (Python/Go agents that never exec a shell)
- Surgical log editing that does not shrink the file
- Direct Windows VSS COM API calls that bypass `vssadmin.exe` entirely (§2.6)
- C2 that never resolves a hostname, connecting by raw IP only (§2.15)

---

<a id="defence-in-depth"></a>
## 5. Defence-in-depth recommendations

Exonerve is one layer. It is most effective alongside:

1. **Immutable / offline backups** — the only reliable ransomware control.
   Every detector above can be evaded; a restorable backup cannot be encrypted
   by an attacker who cannot reach it.
2. **Network segmentation** — limits blast radius when detection is late.
3. **EDR with kernel visibility** — covers the in-memory and API-level gaps an
   OOB polling agent structurally cannot see.
4. **Egress filtering and DLP** — a second, independent control on the
   exfiltration path.
5. **Privileged access management** — raises the cost of reaching the point
   where any of the above evasions become available.
6. **Tested restore procedures** — a backup you have never restored is a
   hypothesis, not a control.

---

<a id="open-items"></a>
## 6. Open items — roadmap

Tracked here with a specific reason each, updated as items close or new ones
are found — per this project's own rule against silently dropping open work.

| Item | Status | Specific reason |
|---|---|---|
| VSS COM API (`IVssBackupComponents`) direct calls, §2.6 | `ACCEPTED` | Requires a kernel-level ETW subscription to the VSS provider — a different privilege model than this agent's design. Evaluated explicitly; no partial coverage simulated in its place. |
| WebServiceC2 direct-to-IP blind spot, §2.15 | `ACCEPTED` | No host-only signal (no packet capture in scope) distinguishes one raw-IP HTTPS connection from another without TLS fingerprinting (JA3/JA4). |
| Medium-cardinality extension-randomisation gap, §2.2 | `MITIGATED` (v3.13), one residual compound gap remains | See §2.2 for the fix (long-window accumulation check) and the specific remaining case (attacker throttles pool introduction across multiple DAYS, not minutes — a real cost, not a free bypass). |
| Beacon-jitter evasion, §2.22 | `ACCEPTED` — evaluated for a fix in v3.13, deliberately not shipped | A median-absolute-deviation-based approach was considered as more jitter-tolerant than coefficient-of-variation, but was NOT validated against real jittered C2 traffic samples. Shipping an unvalidated "improvement" risks a false sense of closure, which is worse than an honestly-named open gap. Real fix needs either labeled jittered-beacon samples to tune against, or frequency-domain analysis — a different statistical approach than a threshold tweak. |
| False-positive corpus at PRODUCTION fleet scale, Priority 1.3 | `PARTIAL` | `tests/corpus/` proves zero false positives at CI-affordable scale; still not telemetry from a real, heterogeneous production fleet. |
| Windows/macOS eventing backends, §3.1 | `PARTIAL` — implemented, not independently verified | This development environment is Linux-only; `watchdog`'s Windows/macOS backends have not been run against a live host as part of any round so far. |
| Rename-pairing (encrypted output attributed to its original filename) | `ACCEPTED` | Neither poll nor event mode pairs a deleted original with the new file it became. Would need inode tracking or a copy-on-write filesystem hook. |
| Kernel-adjacent telemetry (auditd/Sysmon), `kernel_telemetry.py` | `PARTIAL` — parsers real and tested, not validated against a live feed | Tested against realistic, schema-accurate SYNTHETIC samples of both formats; neither a live auditd daemon nor a live Sysmon install exists in this development sandbox. Test against a real feed in isolation before production trust — the benchmark-first approach already agreed on for this whole project. |
| `BackdoorCheck` guest-side invocation, `backdoor_check.py` / `playbook.py` | **`OPEN`, named while wiring the playbook (v3.12)** | `BackdoorCheck` inspects the LOCAL filesystem of whatever machine runs it. The control plane and the compromised guest VM are different machines in this out-of-band design — wiring `BackdoorCheck` directly into the control plane (as an earlier draft almost did) would silently check the control plane's own OS, not the VM's. Needs a remote-invocation path (guest-agent command over the existing telemetry tunnel, reporting results back) that does not exist yet. Left deliberately unwired rather than wired incorrectly. |
| Health-check honesty limitation, `playbook.py`'s `make_default_playbook` | **`ACCEPTED`, named while wiring the playbook (v3.12)** | No read-only "are this VM's services actually healthy" query exists on the hypervisor interface — only action-triggering calls. The default health check instead verifies "no new detection activity for N minutes" via `IncidentManager`, which is a real but different signal than confirmed service uptime. An earlier draft mistakenly wired a destructive recovery action (`restore_snapshot`) as the health check, which would have re-triggered real snapshot restores every poll tick — caught by a dedicated regression test before shipping, not after. |
| Honeytoken deployment gap, §2.24 | `ACCEPTED` | Planting decoy files does nothing without the corresponding `auditctl -w ... -p r` watch rule actually installed — a human/deploy-script action this module deliberately does not take on its own. |
| Attack-specific IR playbook variants | `PLANNED` | v3.12 built the generic state machine (DETECT→ISOLATE→...→CLOSE); sequencing which stages matter most differs by attack type (ransomware vs. credential theft vs. container escape) and isn't built yet. |
| Chain-of-custody for forensic artifacts | `PLANNED` | `BackdoorCheck` gives an action timeline, not hashing/access-logging for artifacts an analyst actually pulls off a VM. |
| Tabletop/drill mode | `PLANNED` | Depends on attack-specific playbook variants existing first. |
| Bandit static-analysis pass, low-severity findings | `ACCEPTED`, triaged not exhaustively fixed | v3.13 resolved all Medium/High findings (XXE-class XML hardening via `defusedxml`, URL-scheme validation on the ticketing poster) and annotated false positives (`B108` detection-signature strings, `B104` bind-all-interfaces as a documented deployment tradeoff). 20 Low-severity findings remain (`try/except/pass` failure-isolation patterns, `subprocess` usage without `shell=True` — both matching this project's own documented fail-safe design) — spot-checked, not individually annotated; re-run `bandit -r guest_production_vm/ host_control_plane/ common/` to review them yourself. |

---

*If you find an evasion not listed here, that is a documentation bug. Please
open an issue.*
