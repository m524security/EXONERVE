# Response to External Review — v3.7.1 → v3.10.0

Every finding from the review passes, what was done, and what is still open.
Nothing is marked fixed unless there is code and a passing test behind it.

> **Reading this document:** Parts 1-3 are the historical record from the
> v3.8.0 and v3.9.0 rounds — their "still open" lists reflect what was true
> *at that time* and are left unedited rather than silently rewritten. **Part
> 4** covers v3.10.0 and supersedes those lists for anything it addresses;
> `DEFENSE_GUIDE.md` §6 (Open items) is the single current source of truth
> for what remains open right now.

---

## Part 1 — Ransomware-specific review

| # | Finding | Status | Evidence |
|---|---|---|---|
| 1 | *"Is crypto-spike entropy or just file count?"* | **Answered: entropy-based** — and improved | It already computed Shannon entropy on 64 KB. v3.8 upgrades it to score the plaintext→ciphertext **transition**, which is strictly better. `EntropyTransitionTracker` |
| 2 | Pre-encryption exfiltration not detected; `cloud_exfil` may be name-matching | **FIXED** | `EgressVolumeMonitor` measures real outbound bytes. Renaming the binary does not evade it. Confirmed: previously there was **no emitter at all** — only `attack_replay.py` injected the event |
| 3 | Slow/staged encryption evades 3σ | **FIXED** | `SlowBurnDetector` — rate-independent cumulative counter (≥150 transitions/hr) |
| 4 | File extension rename monitoring missing | **FIXED** | `ExtensionRenameDetector` — ≥12 new files sharing an uncommon extension in 60 s |
| 5 | No process→file attribution | **FIXED** | `attribute_writers()` attached to `crypto_spike` events; computed only at fire time |
| 6 | Dwell time before detonation | **OPEN — out of scope** | Documented honestly in `DEFENSE_GUIDE.md` §3.4. A host sensor of this design cannot cover weeks of quiet recon |

**Bonus fix the review did not catch:** newly-created files were never entropy-checked, so ransomware writing ciphertext to a *new* filename and deleting the original produced no alert at all. Found by `scripts/ransomware_sensor_demo.py` on first run.

---

## Part 2 — General technical review

| # | Finding | Status | Notes |
|---|---|---|---|
| 1 | Version contradiction (v3.3.0 vs v1.1.0) | **Already fixed before v3.8** — and hardened | Version was consistent in 3.7.1, but was hardcoded in **three** places (`VERSION`, `common/__init__.py`, `pyproject.toml`) while the README claimed "defined once". `common/__init__.py` now reads `VERSION` |
| 2 | "0 FP" claim misleading | **FIXED** | Now reads "0 FP on the included test set" everywhere |
| 3 | Sigma rules: routing wrappers vs field-level | **FIXED** | Explicit table in README: **10 field-level, 8 routing wrappers**, each named |
| 4 | Techniques with no emitter | **PARTLY FIXED** | `cloud_exfil` + `ransomware_esxi` now have live emitters. LSASS, PowerShell, driver-load, cloud-auth remain **labelled "emitter pending"** |
| 5 | ~0.8s RTO is simulated | **Already fixed before v3.8** | 3.7.1 already marked it **simulated** in the Real vs Simulated table |
| 6 | Baselines don't survive restarts | **FIXED** | `BaselineStore` — atomic JSON; entropy priors + slow-burn window persist |
| 7 | No SIEM/ticketing integration | **PARTLY FIXED** | SIEM export added (CEF/ECS/RFC5424). Ticketing and live threat-intel **still missing and now stated as such** |
| 8 | No documented evasions | **FIXED** | `DEFENSE_GUIDE.md` — 255 lines, per-detector, with ACCEPTED/MITIGATED/PLANNED status |

---

## Verification

| Check | Result |
|---|---|
| `verify.py` | 44/44 |
| `pytest tests/` | 119/119 (30 new) |
| `attack_replay.py` | 14/14, 18 Sigma rules, 0 FP on test set |
| `scripts/ransomware_sensor_demo.py` | Green — real filesystem, both directions |
| `tests/fuzz_parsers.py` | Clean |

---

## Still open — recommended next, in priority order

1. **Switch from polling to eventing** (inotify / `ReadDirectoryChangesW`).
   Highest-value item outstanding. Fixes detection latency, CPU cost on large
   trees, and the rename-pairing problem in one change. Today a 2 s poll on a
   multi-million-file tree means the walk itself is the bottleneck.
2. **Randomised-extension ransomware defeats `ExtensionRenameDetector`.**
   It groups by extension; per-file random suffixes bypass it entirely. Add an
   aggregate "unusual-extension population rate" that needs no shared suffix.
3. **`vssadmin` detection is command-line string matching.** Bypassed by
   calling the VSS COM API directly, which real families increasingly do.
   Proper coverage needs ETW/API hooking. Currently `ACCEPTED` and documented.
4. **Intermittent/partial encryption** is the strongest remaining bypass of the
   entropy detector. We sample the first 64 KB, so header-only encryption is
   caught, but sparse interior-block encryption is not. Consider multi-offset
   sampling.
5. **Low-volume C2 over 443 is not detected.** `SocketMonitor` treats 443 as
   benign and `EgressVolumeMonitor` only sees bulk. Beaconing sits in the gap.
6. **Tune `--egress-threshold-mb` per host.** 500 MB / 5 min is wrong for a
   backup server or CDN origin. Baseline before deploying.
7. **Ticketing integration** (Jira / ServiceNow / PagerDuty) and a **live
   threat-intel feed** — the IOC list is still static.
8. **Measure a real KVM failover RTO** to sit alongside the simulated ~0.8 s.
9. **Build a benign-workload FP corpus.** The strongest answer to "what's your
   real false-positive rate" is a second test set of legitimate admin activity
   — backup jobs, bulk gpg, build pipelines, security scans — scored alongside
   the attack replays.

---

---

## Part 3 — Modern attack coverage beyond ransomware (v3.9)

The reviews focused on ransomware. Ransomware is the *loud* part of an
incident — the part you notice. It is rarely where the intrusion starts. v3.9
adds coverage for the classes that dominate how modern breaches actually begin
and spread, applying the same rule throughout: **no rule without a sensor.**

| Attack class | Sensor | Technique | Note |
|---|---|---|---|
| Cloud credential theft via SSRF | `CloudMetadataDetector` | T1552.005 | nginx/python reaching IMDS is the signature |
| Cloud / CI credential files | `CredentialAccessDetector` | T1552.001 | Allowlisted per credential type |
| Kubernetes token theft | ↳ | T1552.007 | Cluster pivot |
| Infostealer (creds + cookies) | ↳ | T1555.003, T1539 | Stolen cookies bypass MFA |
| Container escape | `ContainerEscapeDetector` | T1611 | docker.sock == host root |
| Supply-chain install payload | `SupplyChainDetector` | T1195.002 | Typosquat / dependency confusion |
| C2 over legitimate SaaS | `WebServiceC2Detector` | T1102.002 | Supporting confidence only |
| Protocol tunnelling | `TunnelDetector` | T1572 | Name-based; renaming evades |
| Cryptomining | `CryptominerDetector` | T1496 | CPU alone never fires |
| Destructive wiper | `DataDestructionDetector` | T1485 | Encrypts nothing — entropy sensors are silent |
| Log / history tampering | `LogTamperDetector` | T1070.002/.003 | Size heuristic |
| Reverse shell | `ReverseShellDetector` | T1059.004 | Structural, Linux-only |
| SSH key persistence | `SSHPersistenceDetector` | T1098.004 | Survives password rotation + MFA |

**Coverage: 28 → 42 ATT&CK techniques · 18 → 31 Sigma rules · 14 → 27 replay cases.**

### Two more real bugs found by writing the tests

1. **Browser profile markers never matched real Linux paths.** They required a
   leading slash before the vendor name, which does not appear in
   `~/.mozilla/firefox` or `~/.config/google-chrome`. The infostealer detector
   would have been blind on Linux.
2. **`os.path.basename()` on Linux does not split Windows paths**, so every
   Windows browser-profile comparison silently failed.

Both were caught only because each detector is tested in **both** directions.

### What these detectors do NOT do

Stated here so the technique count is not read as more than it is:

- `TunnelDetector` is name-based — renaming the binary defeats it entirely.
- `WebServiceC2Detector` fails open on direct-to-IP C2; it is labelled
  `detection_confidence: supporting` in every event it emits.
- Credential-file access is a point-in-time `open_files()` sample — sustained
  handles are caught reliably, brief reads between polls can be missed.
- `SupplyChainDetector` misses in-process payloads that spawn no child.
- `ReverseShellDetector` is Linux-only and only inspects shell binaries, so
  non-shell C2 implants evade it.

Per-detector evasion analysis: `DEFENSE_GUIDE.md` §2.10–2.21.

### Updated priority list

1. **Polling → eventing (inotify).** Still the highest-value architectural item,
   and it now matters more: 13 additional sensors amplify the cost of walking
   the tree and the exposure to activity that completes inside one interval.
2. **Name-based allowlists are the common weakness** across the new detectors.
   Moving to executable hash or path verification would harden most of them at
   once.
3. **Benign-workload FP corpus.** Sensor-level benign assertions now exist for
   every detector, which is a real corpus — but it is synthetic. Running against
   a live build server, CI runner and K8s node for a week is the honest next step.
4. Randomised-extension ransomware; `vssadmin` COM bypass; intermittent
   encryption; low-volume C2 over 443 — all unchanged from v3.8, all documented.
5. Ticketing integration and live threat intel — still missing.

---

## Part 4 — v3.10 hardening: architecture + evasion closure

Source: `EXONERVE_NEXT_UPDATE_PROMPT.md`. Same rule as every round before
this one: nothing below is marked fixed without code and a passing test
behind it, and nothing is marked closed if a real gap remains — see the new
`DEFENSE_GUIDE.md` §6 (Open items) for everything not fully closed.

### Priority 1 — Architecture

| # | Item | Status | Evidence |
|---|---|---|---|
| 1.1 | Polling → eventing | **FIXED** | `guest_production_vm/sentry_agent.py`: `_WatchdogFSEventHandler`, `FilesystemMonitor.mode`/`.start()`/`.stop()`/`._scan_event()`/`._scan_poll()`. Both modes share one classification path (`_process_candidate`). Auto-fallback to polling if `watchdog` is unavailable or the OS watch fails to establish — logged, never silent. Tests: `tests/test_eventing.py` (6 tests: 500-file burst captured via the event queue, new-ciphertext-file detection without a tree walk, deletion via `on_deleted` not walk-diff, poll/event verdict parity, fallback-on-Observer-failure). Benchmark: `scripts/eventing_benchmark.py`, results in `DEFENSE_GUIDE.md` §3.1. Compatibility note: the raw `FilesystemMonitor` class still defaults to `mode="poll"` — only `SentryAgent` (the live agent) explicitly requests `mode="auto"`. Found during this work: defaulting the class itself to event mode would have silently broken `scripts/ransomware_sensor_demo.py`, which calls `.scan()` directly without ever calling `.start()`. |
| 1.2 | Ticketing/on-call export | **FIXED** | `common/ticketing_export.py` — `TicketingExporter` (PagerDuty Events API v2 + generic webhook backends), `ticketing_from_env()`. Wired into `host_control_plane/control_center.py`, gated on `AlertManager.raise_alert()` actually returning an `Alert` (not on every event — avoids training on-call to ignore low-signal noise). Tests: `tests/test_ticketing_export.py` (20 tests) — PagerDuty payload shape against the documented schema, severity-vocabulary mapping, dedup-key correlation, and specifically the required failure-isolation tests: a broken poster is caught/counted/never raised, one backend failing doesn't block the other, disabled/unconfigured states are pure no-ops. |
| 1.3 | Benign-workload FP corpus | **FIXED, CI-scale — see DEFENSE_GUIDE §6 for the production-scale caveat** | `tests/corpus/generators.py` (4 scenarios: backup job, CI build server, filesystem indexer, vulnerability port sweep) + `tests/corpus/run_corpus.py` (runs the real live detectors, writes `FP_CORPUS_RESULTS.md`) + `tests/test_fp_corpus.py` (4 CI tests, one per scenario). Current result: **0 false positives across all 4 scenarios.** Full 50,000+-file backup scale is implemented and runnable via `EXONERVE_FP_CORPUS_FULL_SCALE=1`, not run on every CI pass for wall-clock cost reasons. |

**Two real gaps this corpus found, fixed, and disclosed — not folded into a
generic "improvements" bullet, per this project's own rule:**

1. **Build-artifact extensions were missing from `COMMON_EXT`.** The
   `build_server` corpus scenario (a realistic multi-language CI build)
   revealed that `.o`, `.obj`, `.d`, `.a`, `.lib`, `.exp`, `.ilk`, `.pdb`,
   `.rlib`, `.rmeta`, `.class`, `.wasm`, `.map`, `.cc` were not on the
   common-extension allowlist — meaning a real build clustering 90+ new
   `.o` files in one window would have tripped the pre-existing (v3.8)
   `ext_rename` detector. Fixed in `ransomware_sensors.py` (`COMMON_EXT`).
   This predates v3.10 and was not caused by this round's other changes; the
   corpus is what surfaced it.
2. **The novel-extension-rate signal (1.3 below) needed a ratio gate, not
   just a count threshold.** Without it, the same `build_server` scenario
   would have false-positived on the *new* v3.10 detector even after fix #1
   above, because 16 distinct build-output extensions can appear within one
   60-second window on a large parallel build. Fixed by requiring novel
   extensions to also be ≥50% of that window's new files
   (`NOVEL_EXT_MIN_RATIO`), which a build's low-novelty-ratio, high-file-count
   shape fails and per-file-random-extension ransomware's near-1.0-ratio
   shape passes. See `DEFENSE_GUIDE.md` §2.2 for the full mechanism and the
   residual gap this ratio gate does NOT close (medium-cardinality extension
   pools — newly identified, tracked in §6).

### Priority 2 — Specific evasion closure

| # | Item | Status | Evidence |
|---|---|---|---|
| 2.1 | Randomised-per-file-extension ransomware | **FIXED, with a newly-identified residual gap** | `ransomware_sensors.py`: `ExtensionRenameDetector._evaluate_novel_rate`, `NOVEL_EXT_MIN_DISTINCT`, `NOVEL_EXT_MIN_RATIO`. Tests: `tests/test_v3_10_hardening.py::TestNovelExtensionRate` (5 tests) — 20 files/20 distinct extensions in 30s fires `ext_rate_spike` and specifically does NOT also fire the old clustering signal; legitimate project files, a handful of genuinely-new-but-ordinary extensions, and window expiry all stay silent. **Residual gap found while writing these tests, not in the original prompt:** an attacker cycling through a *medium* pool of random extensions (~8-14) can stay under both this signal's threshold and the clustering threshold simultaneously. Documented in `DEFENSE_GUIDE.md` §2.2 and §6, not hidden. |
| 2.2 | Sparse / interior-block encryption bypass | **FIXED, still point-sampling** | `sentry_agent.py`: `file_entropy()` now samples head+middle+tail (not head-only) for files above `SPARSE_SAMPLE_SIZE_MULTIPLIER`× the sample size, returns the max. Tests: `tests/test_v3_10_hardening.py::TestSparseEncryptionSampling` (5 tests) — tail-only and interior-only encryption now caught; small files unchanged; large plaintext files stay low across all three regions. Honest residual gap stated in the docstring and `DEFENSE_GUIDE.md` §2.1: three fixed sample points is not full-file coverage. |
| 2.3 | vssadmin / VSS COM API bypass | **Explicitly evaluated, left ACCEPTED — not simulated** | No code change. Per the prompt's own instruction for this exact case: a real fix needs kernel-level ETW subscription to the VSS provider, a different privilege/platform model than this agent's user-mode design. `DEFENSE_GUIDE.md` §2.6 updated with the specific reason; tracked in §6. |
| 2.4 | Low-volume C2 beaconing | **FIXED** | `modern_threats.py`: `BeaconDetector`, wired into `ModernThreatSuite.scan_all()`. Tests: `tests/test_v3_10_hardening.py::TestBeaconDetector` (4 tests) — fixed ~60s-interval low-jitter beacon fires, irregular human browsing stays silent, too-few-samples stays silent, browser-process allowlist honored via `scan()`. Honestly disclosed evasion in `DEFENSE_GUIDE.md` §2.22: deliberate sleep-jitter (a standard, cheap C2 framework feature) defeats the coefficient-of-variation threshold. |
| 2.5 | Web-service-C2 direct-to-IP blind spot | **Explicitly evaluated, left ACCEPTED — no heuristic substituted** | No code change. Per the prompt's own instruction: no host-only signal without packet-level TLS fingerprinting can close this, and adding a low-confidence heuristic to claim partial coverage was explicitly ruled out. `DEFENSE_GUIDE.md` §2.15 updated with the specific reason; tracked in §6. |

### Control-plane wiring

Both new event types (`ext_rate_spike`, `beacon`) are scored in
`host_control_plane/control_center.py` (`SCORE_WEIGHTS`) and mapped to
ATT&CK in `common/mitre_attack.py` — not emitted and forgotten. Tests:
`tests/test_v3_10_hardening.py::TestV310ControlPlaneWiring`.

### Verification (this round)

| Check | Result |
|---|---|
| `pytest tests/` | 233/233 (46 new: 16 hardening, 20 ticketing, 6 eventing, 4 FP-corpus) |
| `verify.py` | 44/44, unchanged |
| `attack_replay.py` | 27/27 techniques, 31 Sigma rules, 0 FP — **unchanged from v3.9; see note below** |
| `tests/corpus/run_corpus.py` | 0/4 scenarios false-positive |

**Honest note on `attack_replay.py`:** its scenario set was not extended
with replay cases for `ext_rate_spike` or `beacon` this round — those two
detectors are proven with direct unit tests
(`tests/test_v3_10_hardening.py`) and the FP corpus, but not yet through the
full Sigma-rule/control-center replay pipeline the way v3.8/v3.9 detectors
are. Tracked as a specific follow-up rather than left unstated.

### What's still open — see `DEFENSE_GUIDE.md` §6 for full detail

1. Medium-cardinality extension-randomisation gap (§2.2) — **newly found
   this round**, not in the original prompt.
2. VSS COM API direct calls (§2.6) — `ACCEPTED`, needs ETW, out of scope.
3. WebServiceC2 direct-to-IP (§2.15) — `ACCEPTED`, needs packet-level
   fingerprinting, out of scope.
4. Beacon-jitter evasion (§2.22) — `ACCEPTED` by design this round.
5. FP corpus at real production-fleet scale, not just CI-affordable
   synthetic scale.
6. Windows/macOS eventing backends implemented (via `watchdog`) but not
   independently verified on a live Windows/macOS host — this development
   environment is Linux-only.
7. `attack_replay.py` / Sigma-rule replay coverage for the two new v3.10
   event types.
8. Rename-pairing (encrypted output attributed to its original filename) —
   unchanged, out of scope for either poll or event mode as currently designed.

---

*The foundation was sound. v3.8 closed the distance between what the
documentation claimed and what the code did. v3.9 widened the aperture past
ransomware. v3.10 fixed the highest-leverage architectural gap (polling),
closed two of five named evasions for real, evaluated the other three
explicitly rather than ignoring them, and found two new real bugs — a
missing build-artifact allowlist entry and a false-positive-prone threshold
— by building the false-positive corpus the v3.9 round said was still
needed. Same rule throughout: no claim without code and a test behind it,
and no gap left undocumented.*
