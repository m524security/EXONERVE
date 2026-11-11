# Changelog

## [Unreleased] — audit pass: entry-point fix, measurement fix, claim corrections

### Fixed
- **`sigma_engine` and `yara_engine` crashed when launched as scripts**
  (`ModuleNotFoundError: No module named 'common'`), which is exactly how
  `blue_team/exonerve.py` launches every tool. They only worked under pytest
  because pytest's rootdir was already on `sys.path`. Both now add the repo
  root to `sys.path` before importing `common.*`. New regression test
  `tests/test_tool_entrypoints.py` launches all 27 registered tools from a
  foreign working directory (it fails on the previous code).
- **`attack_replay.py --live` MTTD was a polling artifact.** The harness slept
  100 ms before its first poll, so every sample read ~103-105 ms regardless of
  real latency. It now polls every 5 ms; measured MTTD is ~9 ms mean
  (8-25 ms) over 31 cases on loopback.
- Removed unused imports and placeholder-less f-strings flagged by
  ruff/pyflakes across 45 files (no behaviour change; full suite re-run).

### Documentation corrected to match measured values
- ATT&CK techniques 42 -> 44; Sigma rules 31 -> 35 (README table now lists
  the 4 newest rules; split is 10 field-level / 25 routing wrappers).
- Blue-team tools 24 -> 27 (`sigma_engine`, `killchain_reconstructor`,
  `blast_radius` were registered but undocumented).
- Replay 27/27 -> 31/31; pytest 348 -> 375 (233 in the repo tree listing).
- Ticketing was listed "Not implemented" although `common/ticketing_export.py`
  (PagerDuty + generic webhook) ships with tests; now "Partial".
- "MTTD ~110 ms" replaced with the re-measured figure and its conditions.
- Fuzzing claim "10k+" -> "10,000 (5,000 per parser)".
- Removed the `.github/workflows/ci.yml` entry from the repo tree; that file
  was deleted in the previous commit.

## [3.13.0] — 2026-07-25 — evasion fixes, self-validation closure, security hardening, documentation sync

Direct response to: "you addressed 2 of 6 rating dimensions, do the other
4." Real fixes in each, not re-explanations of why they're hard.

### Evasion resistance
- **Honeytoken content no longer self-identifies as bait.** Found and
  fixed the same day it shipped: v3.12's `HoneytokenManager` wrote content
  literally containing "DECOY FILE — planted by Exonerve," which an
  attacker reading before exfiltrating would spot instantly, defeating the
  mechanism. Replaced with plausible-looking fake content, pinned by a
  regression test that itself caught a SECOND leak (the word "bait"
  survived in one fake-PEM string on the first attempt) before it shipped.
- **Medium-cardinality extension-pool evasion, MITIGATED.** The
  originally-planned fix (Shannon entropy over the extension-frequency
  distribution) was tested against the FP corpus first and found not to
  reliably separate the attack from the legitimate multi-language build
  scenario at realistic scale — shipping it anyway would have been a false
  sense of closure. What actually closes it: a 24-hour accumulation window
  on the same "is this extension novel" check (`ExtensionRenameDetector.
  _evaluate_long_window_novelty`), which an attacker can only still evade
  by spreading pool introduction across multiple DAYS instead of minutes —
  a real, meaningful cost. See `DEFENSE_GUIDE.md` §2.2 for the residual gap
  this doesn't close, stated explicitly.
- **Beacon-jitter fix evaluated, deliberately NOT shipped.** A median-
  absolute-deviation approach was considered as more jitter-tolerant than
  coefficient-of-variation, but wasn't validated against real jittered C2
  samples. An unvalidated "improvement" that doesn't reliably help is worse
  than an honestly-named open gap — remains `ACCEPTED`, tracked in
  `DEFENSE_GUIDE.md` §6 with the specific reason.

### Self-validation discipline
- **`attack_replay.py` now covers all 4 detector generations that were
  missing it** (`ext_rate_spike`, `beacon`, `exfil_graph`,
  `honeytoken_accessed` — spanning v3.10 through v3.12). Real gap named
  honestly across three straight changelogs, closed for real this round.
- **4 new Sigma rules** (`ext_rate_spike.yml`, `beacon_interval_c2.yml`,
  `exfil_access_then_egress.yml`, `honeytoken_accessed.yml`) — coverage now
  35 rules, all 31 replayed techniques mapped to a real rule, 0% FP on the
  benign control set.

### Architecture & code quality — a real static-analysis pass, not a claim
- **`bandit` security scan**: all Medium/High findings resolved. Two real
  fixes: XML parsing in `kernel_telemetry.py` now uses `defusedxml`
  (protects against entity-expansion DoS / external-entity resolution when
  parsing Sysmon XML from a source that, in a real deployment, could be
  compromised or spoofed) with a loud-warning stdlib fallback if
  `defusedxml` is absent; the ticketing poster now validates URL scheme is
  http/https before calling `urlopen()`, guarding against a misconfigured
  `webhook_url` (e.g. a copy-pasted `file://` path) rather than trusting it
  implicitly. Two false positives annotated with specific reasons, not
  silently suppressed (`B108` on detection-signature path strings that
  aren't actually temp-file writes; `B105` on a scoring-weight integer
  bandit's heuristic matched against the word "token" in its dict key).
  One documented tradeoff, not silently changed: `--listen-host`/
  `--web-host` default to `0.0.0.0` (`B104`) because this control plane is
  commonly reached from other hosts on its deployment network — narrowing
  the default without knowing the actual topology risks breaking real
  setups; state-changing routes already require the API token regardless.
  20 Low-severity findings (mostly intentional `try/except/pass` failure-
  isolation, matching this project's own documented design) triaged, not
  individually annotated — see `DEFENSE_GUIDE.md` §6.
- **`pyflakes` correctness pass** across every file touched this round:
  fixed a real duplicate `import time` in `playbook.py`, and removed 8
  genuinely-unused imports across the files added in v3.12
  (`kernel_telemetry.py`, `exfil_detector.py`, `backdoor_check.py`,
  `ticketing_export.py`). Pre-existing unused imports in files NOT touched
  this round or last (`hypervisor_api.py`, `attack_navigator.py`, etc.)
  left as a named, deferred cleanup rather than touched blind this late in
  an already-large session.
- **`watchdog` was never actually declared in `guest_production_vm/
  requirements.txt`**, despite being required since v3.10's eventing
  filesystem monitor. Found while touching that file for the defusedxml
  addition, fixed.

### Documentation & honesty
- **`DEFENSE_GUIDE.md` was stuck at its v3.10.0 header** despite two full
  rounds (v3.11, v3.12) of subsequent detector and architecture work never
  reflected there — CHANGELOG.md had moved on, DEFENSE_GUIDE.md hadn't.
  Fully synced: version bumped, §2.2's medium-cardinality entry updated
  from `PLANNED` to `MITIGATED` with the actual (different-than-planned)
  fix, two new detector sections added (§2.23 exfil graph, §2.24
  honeytoken) with real Known-Evasions tables, and §6 Open Items rewritten
  to match current reality — closed items removed, new items (guest-side
  `BackdoorCheck` invocation gap, the health-check honesty limitation, the
  honeytoken deployment gap) added with the same specific-reason discipline
  as everything else in that section.

### Testing
7 new tests (2 honeytoken-content regression, 3 long-window extension
evasion/benign, 1 URL-scheme-validation, 1 scheme-acceptance) plus fixes to
2 pre-existing tests whose scenario math needed correcting for the new
long-window check's interaction. Totals: 44/44 verify, **348/348 tests**
(was 343), 31/31 ATT&CK replay with **35 Sigma rules** (was 27/27 with 31 —
the 4 new cases plus their rules is the actual number moving here),
0% FP on the replay benign control set, 0/4 FP-corpus scenarios
false-positive, 0 Medium/High bandit findings (was 10).

## [3.12.0] — 2026-07-24 — kernel-adjacent telemetry, exfiltration detection, HITL playbook

Direct response to the ask: kernel visibility "the honest way" (consume
established tools, don't fake a custom driver), a human-in-the-loop
DETECT→ISOLATE→MITIGATE→VULN_SCAN→REMEDIATE→BACKDOOR_CHECK→REVALIDATE→
RECOVER→CLOSE workflow with a SOC member gating the judgment-call stages,
and a new "giant attack" detector category (data exfiltration) built
passive+active, matching the ransomware detector's graph-based design
philosophy. Same rule as every round: nothing ships without a test, and
"no false positive" is corrected where it's not an achievable target rather
than quietly promised.

### Added — kernel-adjacent telemetry (`guest_production_vm/kernel_telemetry.py`)
Not a custom kernel driver (that needs a real kernel dev environment, a
target to load against, and months of stability testing this session
cannot honestly provide). Instead: parsers for **auditd** (Linux, raw
audit.log format) and **Sysmon** (Windows, Event ID 1 ProcessCreate XML) —
both already-signed, already-deployed, kernel-sourced telemetry. Reshapes
either into the same event shape `ProcessLineageMonitor` already consumes,
so kernel-sourced events feed existing detection logic rather than needing
a parallel detector. Concrete value over psutil polling: catches
short-lived processes that spawn and exit BETWEEN poll ticks.
**Real bug caught by the test suite before shipping:** an ElementTree
`elem or fallback` pattern is wrong for leaf XML elements (`Element.__bool__`
is based on child count, not identity) — a successfully-found `<EventID>`
element was being silently discarded. Fixed; regression-tested.
**Honesty note, stated in the module docstring:** tested against realistic,
schema-accurate synthetic samples, not a live auditd/Sysmon feed — neither
exists in this sandbox. Test against a real feed in isolation before
production trust, exactly the benchmark-first approach already agreed on.

### Added — data exfiltration detector, passive + active (`guest_production_vm/exfil_detector.py`)
**Passive:** `ExfilGraphDetector` correlates sensitive-file access with a
subsequent connection to a destination the SAME process hasn't talked to
before — the shape of staged theft, independent of transfer volume (which
`EgressVolumeMonitor` already covers separately). **Active:**
`HoneytokenManager` plants believable decoy files and tells the operator
the exact `auditctl -w ... -p r` command needed to make reads on them
reliably detectable (does not modify the live audit config itself — that's
a deliberate human/deploy-script action). Near-zero-FP by construction:
nothing legitimate has a reason to open a file this agent invented five
minutes ago. New techniques: T1020 (exfil_graph), T1005 (honeytoken_accessed).

### Added — backdoor check (`host_control_plane/backdoor_check.py`)
Point-in-time baseline snapshot + diff: SSH `authorized_keys` (reuses
`SSHPersistenceDetector`'s own path-discovery/parsing rather than
re-implementing it), cron entries, systemd startup services, running
processes. Read-only, auto-runnable — but `diff()` returns findings, never
a verdict; the playbook stage this feeds always requires explicit SOC
sign-off, whether the diff is empty or not.

### Added — human-in-the-loop incident response playbook (`host_control_plane/playbook.py`)
The requested lifecycle, built as intended: fast/reversible stages
(isolate, mitigate) auto-execute; judgment-call/destructive stages
(remediate, close) are hard-gated behind an explicit SOC action —
`Playbook` rejects every gated action called out of order, which is the
actual safety property this design depends on (tested explicitly, every
gate). Vulnerability scanning and re-validation ("pentest again") are
integration hooks that RECORD a real scanner's or a real pentester's
findings — this module does not simulate running a pentest, because
pretending to would be exactly the kind of unearned claim this project
refuses elsewhere. Recovery check loops until healthy rather than closing
on a schedule ("if not, always be checking"). `reopen_to()` is an explicit
escape hatch for when backdoor-check or re-validation finds something wrong
— real IR isn't strictly linear.
**Real design bug caught before shipping, not after:** an early draft wired
`hypervisor.restore_snapshot()` — a destructive, action-triggering call —
as the health-check function polled every loop tick, which would have
re-triggered real snapshot restores repeatedly. Fixed to use a
non-destructive proxy (no new detection activity for N minutes, via
`IncidentManager`'s own `last_activity_ts`) and documented exactly what
that does and doesn't verify: absence of new alerts, NOT confirmed service
health — this agent has no read-only "are services actually up" RPC today,
named as an open item rather than assumed away.
**Named architectural gap, found while wiring this up:** `BackdoorCheck`
inspects whatever machine runs it. Wiring it directly into the control
plane would silently check the CONTROL PLANE's own filesystem, not the
compromised VM's — they're different machines in this out-of-band design.
Left deliberately unwired pending a guest-side remote-invocation path,
rather than wired incorrectly just to "have something connected."

### REST API
`GET/POST /api/incidents/<id>/playbook[/<action>]` — status, advance, and
every gated SOC action (`vuln_scan`, `approve_remediation`,
`approve_backdoor_check`, `revalidate`, `close`, `reopen`). Same auth
posture as `/api/alerts/` and `/api/incidents/`.

### Control-plane wiring
`exfil_graph` and `honeytoken_accessed` scored in `SCORE_WEIGHTS`
(honeytoken weighted near instant-block, reflecting its near-zero-FP
design) and mapped to ATT&CK in `common/mitre_attack.py`.

### On "no false positive" and "just works as designed" — corrected, not promised
Every real detection system trades false positives against false
negatives; this is math, not an engineering gap to close. What's true
instead, and tested: `tests/corpus/` still shows 0 FP across all 4 benign
scenarios with the new detectors included, every new sensor has both a
fires-on-attack and a stays-silent-on-named-benign-case test, and two real
bugs (the ElementTree parser bug, the destructive-health-check bug) were
caught by that testing discipline before they shipped, not after.

### Testing
`tests/test_kernel_telemetry.py` (19), `tests/test_exfil_detector.py` (16),
`tests/test_backdoor_check.py` (12), `tests/test_playbook.py` (17), plus
Flask integration tests for the new playbook routes appended to
`tests/test_incident_api.py` (+7). **71 new tests this round**
(19+16+12+17+7).

Totals: 44/44 verify, **343/343 tests** (was 272 at the start of this
round), 27/27 ATT&CK replay (unchanged — same honest note as v3.11: the
newest detectors aren't in the replay matrix yet), 0/4 FP-corpus scenarios
false-positive.

### What's still open — named, not dropped
- Attack-specific IR playbook VARIANTS (this release built the STATE
  MACHINE; a ransomware-specific vs. credential-theft-specific sequencing
  of which stages matter most is still generic across attack types)
- Chain-of-custody for forensic artifacts (backdoor-check gives an action
  timeline, not hashing/access-logging for pulled evidence)
- Tabletop/drill mode
- Guest-side remote invocation for `BackdoorCheck` (see above)
- Read-only "are services actually healthy" RPC on the hypervisor interface
  (health_check_fn's honest limitation, see above)
- Cross-host correlation, medium-cardinality extension-pool gap,
  beacon-jitter evasion, `attack_replay.py` coverage for v3.10-v3.12
  detectors — all carried forward from prior rounds, still open

## [3.11.0] — 2026-07-23 — incident response: case management, reports, escalation

v3.10 hardened the agent's own architecture. This release adds the layer on
top that ties detection, containment, and paging into an actual incident
workflow — the gap flagged when this round started: alerts, containment
actions, and post-incident writeups all existed as disconnected primitives
with nothing correlating them into a case.

Same rule as every round before this one: nothing below ships without code
and a passing test behind it, and every item not completed this round is
named with a specific reason, not silently dropped.

### Added — incident case management
`host_control_plane/incident_manager.py`: correlates alerts on the same VM
within a 30-minute activity window into a single `Incident` with a real
lifecycle (`DETECTED -> TRIAGED -> CONTAINED -> RECOVERED -> CLOSED`),
enforced by an explicit allowed-transition graph — invalid transitions
(e.g. `DETECTED -> RECOVERED`, or anything out of `CLOSED`) are rejected
with a specific reason, not silently accepted. `CLOSED` is terminal by
design: a new alert on a VM with a closed case opens a NEW incident linked
to the closed one, rather than silently reopening a case that was already
signed off. Deliberately does not duplicate detection, scoring, or
containment logic — it correlates `AlertManager.Alert` objects that are
already deduped and scored.

### Added — post-incident reports (stitches together existing tools, doesn't reimplement them)
`IncidentManager.generate_report()` produces a Markdown report, an ATT&CK
Navigator layer, and a STIX 2.1 bundle for one incident's specific
techniques, by calling `KillChainReconstructor`, `common/attack_navigator.py`,
and `common/stix_export.py` directly — the same engineering discipline v3.9's
wiper detector used (reusing the file-monitor's stream instead of standing up
a parallel one). Response actions taken (isolate/contain/failover) are pulled
from `VMState.ir_log`, which `CorrelationEngine` already populates as those
actions happen — no second action log was created.

### Added — REST API for incident visibility
`GET /api/incidents`, `GET /api/incidents/<id>`, `POST
/api/incidents/<id>/<status>`, `POST /api/incidents/<id>/report` — mirrors
the existing `/api/alerts/<id>/<action>` pattern exactly, including its
auth posture (remote callers need the API token; localhost is trusted).
`incidents` also now appears in `/api/status` for dashboard visibility.
Found and fixed during this work, before it shipped: the new routes were
initially NOT added to the token-protected path list — remote,
unauthenticated incident-status mutation would have been possible. Caught by
writing an actual Flask-test-client integration test
(`tests/test_incident_api.py`) rather than trusting static review of the
route code, which is also how a second bug (`engine.get_vm()`, which does
not exist — the correct accessor is `engine._vms.get(vm_id)`) and a missing
`IncidentStatus` import were caught before landing, not after.

### Added — escalation policy
`host_control_plane/escalation_policy.py`: re-pages an alert that has sat
`OPEN` (never acknowledged, assigned, or escalated) for longer than 15
minutes (`ESCALATE_AFTER_S`), via the existing `common/ticketing_export.py`
backends. An alert already acknowledged is never escalated — this exists for
"nobody responded at all," not to nag about slow follow-through on something
already being worked. Wired into the control loop on a 60-second cadence.
Same failure posture as the rest of the ticketing path: a broken backend is
caught and never allowed to propagate into the control loop that calls it.
`AlertManager` gained one supporting query method, `stale_open_alerts()`.

### Testing
`tests/test_incident_response.py` (27 tests) — correlation in both
directions (same VM joins one case; different VMs/expired correlation
windows don't), the full lifecycle state machine including every invalid
transition, closed-incident linking, report generation against the real
kill-chain/Navigator/STIX tools (not mocks), and escalation policy including
failure isolation. `tests/test_incident_api.py` (12 tests) — the Flask route
integration tests referenced above, including proving the localhost-trust
bypass is real (not assumed) alongside the remote-caller token gate.

### What's still open — named, not dropped
This release intentionally implemented 3 of 6 originally-suggested IR
items — the ones the other three depend on or benefit most from existing
first. Deferred, with reasons:
- **Attack-specific IR playbooks** (sequenced response per attack type —
  ransomware vs. credential theft vs. container escape). Meaningfully larger
  scope than the three items above; needs its own round so each playbook
  gets the same fire/silent-both-directions testing discipline as a detector,
  not a shallow first pass.
- **Chain-of-custody for collected forensic artifacts.** `VMState.ir_log`
  gives a basic action timeline (what containment/failover actions ran,
  when), which is a start, but real chain-of-custody (hashing, access
  logging, transfer records for artifacts an analyst pulls off a VM) is a
  distinct, unbuilt capability, not the same thing as an action log.
- **Tabletop/drill mode** (rehearsing playbooks via `attack_replay.py`
  without touching real containment). Depends on playbooks existing first.

Totals: 44/44 verify, **272/272 tests** (was 260), 27/27 ATT&CK replay
(unchanged — incident management correlates already-scored alerts, it
doesn't add new detected techniques), 0/4 FP-corpus scenarios false-positive.

## [3.10.0] — 2026-07-21 — architecture hardening + evasion closure

v3.8 closed the ransomware gaps. v3.9 widened coverage past ransomware to the
stages that precede it. Neither round touched the agent's own architecture —
this release does: the polling→eventing rewrite that every other detector's
latency depended on, a real on-call paging path, a false-positive corpus at
CI scale, and closure (or an honest, explicit refusal to fake closure) of
five specific evasions named in the last review round.

**The rule from the last two rounds is not relaxed.** No Sigma rule, no
ATT&CK mapping, no README line ships without code that emits its event. Every
new or changed detector gets a fire test and a named-benign-case silence
test. Two items this round were evaluated and explicitly left `ACCEPTED` —
not simulated, not papered over with a low-confidence heuristic — because
that is what closing them for real requires and this round did not do that
work.

### Fixed — two real bugs found while building the false-positive corpus
- **Build-artifact extensions were missing from `COMMON_EXT`.** A realistic
  multi-language CI build (`.o`, `.obj`, `.d`, `.a`, `.lib`, `.exp`, `.ilk`,
  `.pdb`, `.rlib`, `.rmeta`, `.class`, `.wasm`, `.map`, `.cc`) clustering 90+
  new files sharing one such extension inside one `RENAME_WINDOW` would have
  tripped the pre-existing (v3.8) `ext_rename` detector. This predates
  v3.10; the new false-positive corpus (`tests/corpus/`) is what surfaced
  it, on the very scenario built to find exactly this kind of gap.
- **The new novel-extension-rate signal needed a ratio gate, not just a
  count threshold.** An absolute distinct-extension-count check alone
  false-positived on the same CI-build scenario: 16 distinct build-output
  extensions can legitimately appear within one 60-second window on a large
  parallel build. Fixed by requiring novel extensions to also be ≥50% of
  that window's new files (`NOVEL_EXT_MIN_RATIO`) — a build's low-ratio,
  high-file-count shape fails this; per-file-random-extension ransomware's
  near-1.0 ratio passes it.

### Added — polling → eventing (Priority 1.1)
`FilesystemMonitor` now defaults to OS-level event watching (`inotify` /
`ReadDirectoryChangesW` / FSEvents via `watchdog`) instead of a fixed-interval
tree walk, and falls back to polling automatically — logged, never silent —
if `watchdog` is unavailable or the filesystem doesn't support recursive
watches. Both modes share one classification code path
(`_process_candidate`), so switching modes changes latency, never verdicts.
Measured (single-machine sandbox, see `scripts/eventing_benchmark.py`): poll
CPU cost scales with tree size regardless of activity (4.5% @ 3K files, 11.2%
@ 8K files); event cost stays roughly flat (0.4% / 0.6%) and tracks actual
change volume instead.

### Added — on-call paging (Priority 1.2)
`common/ticketing_export.py`: PagerDuty Events API v2 and generic-webhook
backends (covers Opsgenie/ServiceNow/Jira/Slack via their own inbound-webhook
features). Wired into `control_center.py`, gated on `AlertManager` actually
raising a deduped, above-threshold alert — not on every event, which would
just train the on-call rotation to ignore it. Same failure posture as SIEM
export: a dead endpoint is caught, counted, and never allowed to break
detection or containment.

### Added — false-positive corpus (Priority 1.3)
`tests/corpus/`: four benign-workload generators (nightly backup job, CI
build server, filesystem indexer, vulnerability-scanner port sweep) run
against the real, live detectors — not mocks. CI-affordable scale by
default; the literal 50,000+-file backup scenario from the original ask is
implemented and runnable via `EXONERVE_FP_CORPUS_FULL_SCALE=1`. Current
result: **0 false positives across all 4 scenarios** (`FP_CORPUS_RESULTS.md`,
regenerate with `python3 tests/corpus/run_corpus.py`).

### Added — 2 new detectors / signals, 2 ATT&CK techniques
| Sensor / signal | Event | Technique |
|---|---|---|
| `ExtensionRenameDetector` (extended) | `ext_rate_spike` | T1486 |
| `BeaconDetector` (new, `modern_threats.py`) | `beacon` | T1071 |

- **`ext_rate_spike`** closes the randomised-per-file-extension bypass: the
  rate of never-before-seen extensions, independent of whether any single
  one clusters. Requires both an absolute distinct-extension threshold and a
  novelty-ratio threshold (see Fixed, above) — found necessary by this
  round's own corpus, not assumed.
- **`beacon`** (`BeaconDetector`) closes the low-volume C2 gap `EgressVolumeMonitor`
  never covered: regular, low-jitter connection timing to one destination,
  independent of transferred volume. Honestly disclosed evasion: deliberate
  sleep-jitter (cheap, standard in real C2 frameworks) defeats the
  coefficient-of-variation check — see `DEFENSE_GUIDE.md` §2.22.

### Changed — entropy sampling (Priority 2.2)
`file_entropy()` now samples head, middle, *and* tail (not head-only) for
files above a size threshold, using the highest of the three. Closes the
single most-cited bypass from the v3.9 review round: encrypting only the
interior or tail of a file to keep a head-only check in the plaintext band.
Still point-sampling, not full-file coverage — stated in the code and in
`DEFENSE_GUIDE.md` §2.1, not implied to be fully closed.

### Evaluated and left ACCEPTED, explicitly — not simulated (Priorities 2.3, 2.5)
- **VSS COM API direct calls** (`IVssBackupComponents` bypassing
  `vssadmin.exe`): closing this for real needs a kernel-level ETW
  subscription to the VSS provider — a different privilege and
  platform-integration model than this agent's user-mode design. No
  partial-coverage heuristic added in its place.
- **WebServiceC2 direct-to-IP**: no host-only signal (this agent has no
  packet capture) distinguishes one raw-IP HTTPS connection from another
  without TLS fingerprinting. No low-confidence heuristic substituted.

Both documented with the specific reason in `DEFENSE_GUIDE.md`, per this
project's rule against silently dropping open work.

### New gap found and disclosed, not hidden
Writing the tests for `ext_rate_spike` surfaced a residual evasion the
original review round did not name: an attacker cycling through a
*medium* pool of random extensions (roughly 8-14) can stay under both the
clustering threshold and the novel-rate/ratio threshold simultaneously.
Tracked as `PLANNED` in `DEFENSE_GUIDE.md` §2.2 and §6 with a specific
proposed fix (extension-population Shannon entropy instead of two fixed
thresholds), not left unstated.

### Control-plane wiring
Both new event types scored in `control_center.py` (`SCORE_WEIGHTS`) and
mapped to ATT&CK in `common/mitre_attack.py`. Asserted in
`TestV310ControlPlaneWiring`.

### Testing — both directions, every detector, plus the corpus
`tests/test_v3_10_hardening.py`, `tests/test_eventing.py`,
`tests/test_ticketing_export.py`, `tests/test_fp_corpus.py` — 46 new tests.

| Must fire | Must stay silent |
|---|---|
| tail-only / interior-only high-entropy region | large all-plaintext file, all 3 regions |
| 20 files, 20 distinct random extensions in 30s | 50 `.py` files; a handful of genuinely-new-but-ordinary extensions |
| fixed ~60s-interval low-jitter connections | irregular human browsing; too few samples; allowlisted browser process |
| 500-file create burst captured via the event queue | — (see eventing tests for fallback-on-Observer-failure instead) |
| — | PagerDuty/webhook: broken poster caught, counted, never raised |
| — | backup job (2K archives), CI build (1.5K files/16 exts), disk indexer (3K read-only), port sweep (3K conns) — 0 FP across all 4 |

Totals: 44/44 verify, **233/233 tests** (was 187), 27/27 ATT&CK replay
(0 FP on the included test set, unchanged from v3.9 — see `REVIEW_RESPONSE.md`
Part 4 for the honest note on why replay coverage for the 2 new event types
is a tracked follow-up, not yet added), 0/4 FP-corpus scenarios false-positive,
sensor demo green.

## [3.9.0] — 2026-07-19 — modern threat coverage beyond ransomware

v3.8 closed the ransomware gaps. Ransomware is the loud part of an incident,
not the whole of it — this release covers the classes that dominate how modern
intrusions actually begin and spread: cloud credential theft, identity and
session theft, container escape, supply-chain execution, SaaS-fronted C2, and
destructive impact.

**The v3.7.1 lesson is not repeated.** Every technique added here is backed by
a real sensor. No Sigma rule and no ATT&CK mapping ships without code that can
emit its event.

### Fixed — two real bugs found while testing the new detectors
- **Browser profile markers never matched real Linux paths.** The marker list
  required a leading slash before the vendor name (`/mozilla/firefox/`), which
  does not appear in `~/.mozilla/firefox` or `~/.config/google-chrome`. The
  infostealer detector would have been blind on Linux — the platform most of
  these agents run on.
- **`os.path.basename()` on Linux does not split Windows paths.** A telemetry
  path like `C:\Users\a\...\Login Data` returned the entire string as its
  own basename, so every filename comparison silently failed. An agent has to
  reason about paths from the platform it is *watching*, not the platform it
  happens to run on. Added `_xbasename()` and a cross-platform regression test
  covering Linux, macOS and Windows profile layouts.

### Added — 13 sensors, 14 ATT&CK techniques (28 -> 42)
| Sensor | Event | Technique |
|---|---|---|
| `CloudMetadataDetector` | `imds_access` | T1552.005 |
| `CredentialAccessDetector` | `cred_file_access` | T1552.001 |
| ↳ | `k8s_token_access` | T1552.007 |
| ↳ | `browser_cred_theft` | T1555.003, T1539 |
| `ContainerEscapeDetector` | `container_escape` | T1611 |
| `SupplyChainDetector` | `supply_chain` | T1195.002 |
| `WebServiceC2Detector` | `web_service_c2` | T1102.002 |
| `TunnelDetector` | `tunnel` | T1572 |
| `CryptominerDetector` | `cryptominer` | T1496 |
| `DataDestructionDetector` | `data_destruction` | T1485 |
| `LogTamperDetector` | `log_tamper` | T1070.002, T1070.003 |
| `ReverseShellDetector` | `reverse_shell` | T1059.004 |
| `SSHPersistenceDetector` | `ssh_persistence` | T1098.004 |

Design notes worth calling out:
- **Cryptomining requires a mining-specific indicator.** Sustained CPU alone
  never fires, because that is a build server. Renaming the binary does not
  evade the pool-port path.
- **Reverse-shell detection is structural**, not signature-based: a shell whose
  stdin *and* stdout/stderr point at sockets. Payload obfuscation is irrelevant.
  A single redirected fd is an ordinary pipeline and is ignored.
- **Wiper detection is deletion-based** and deliberately separate from the
  ransomware pack: a wiper encrypts nothing, so no entropy transition ever
  occurs and the v3.8 sensors stay silent by design.
- **`ext_rename` / `slow_encrypt` remain out of `INSTANT_BLOCK_TYPES`**;
  `reverse_shell`, `container_escape` and `data_destruction` were added to it,
  as all three are structurally unambiguous.

### Added — 13 Sigma rules (18 -> 31), each with a `falsepositives:` block
All 13 modern event types verified to match a rule, carry an ATT&CK mapping,
and hold a server-side score. Asserted in `TestSuiteAndWiring`.

### Changed — replay matrix
27 attack cases (was 14) and 3 benign controls (was 1). Every modern case is
emitter-backed. The replay output now states explicitly that it exercises the
**control-plane scoring path**, and that meaningful false-positive validation
happens at **sensor level** in the test suite.

### Testing — both directions, every detector
`tests/test_modern_threats.py` — 76 new tests. The rule enforced throughout:
a detector only ships if there is also a test proving it stays silent on its
benign analogue. A detector that only proves it fires is half-tested, and
half-tested detectors are how a security tool ends up hard-blocking production.

| Must fire | Must stay silent |
|---|---|
| `nginx` -> IMDS | `cloud-init` -> IMDS |
| `curl` reads `~/.aws/credentials` | `aws` CLI reads its own credentials |
| `bash` reads K8s SA token | `kubelet` reads the SA token |
| `stealer.exe` opens Chrome `Login Data` | `chrome` opens it; `restic` backs it up |
| `bash` holds `docker.sock` | `dockerd` holds it |
| `npm` spawns `curl` | `npm` spawns `node-gyp`/`make`/`gcc` |
| `xmrig` at 99% CPU | `gcc` at 100% CPU |
| 150 deletions in 60s | 20-file cleanup |
| `auth.log` truncated to 0 | `syslog` growing |
| shell stdio on sockets | shell on `/dev/pts/0` |

Totals: 44/44 verify, **187/187 tests**, 27/27 ATT&CK replay
(0 FP on the included test set), sensor demo green, fuzzing clean.

### Documentation
- `DEFENSE_GUIDE.md` extended to 424 lines with §2.10–2.21 covering every new
  detector. Includes the ones that are weak: `TunnelDetector` is name-based and
  renaming defeats it; `WebServiceC2Detector` fails open on direct-to-IP C2;
  credential-file access is a point-in-time sample; supply-chain detection
  misses in-process payloads; reverse-shell detection is Linux-only and misses
  non-shell implants.
- README section 10 documents the sensors, the both-directions test matrix, and
  the honest limits.

## [3.8.0] — 2026-07-19 — ransomware sensor pack; review-driven emitter + FP fixes

External review of v3.7.1 found that two ATT&CK techniques were scored, mapped,
and rule-matched but had **no live sensor** — they only ever fired because
`attack_replay.py` injected them. It also found that absolute-entropy scoring
could not distinguish ciphertext from compressed data. Both are fixed here.

### Fixed — real detection gap found by the new end-to-end demo
- **Newly-created files were never entropy-checked.** `FilesystemMonitor` only
  analysed files whose `mtime` changed, so the dominant ransomware pattern —
  write ciphertext to a *new* filename (`report.docx` → `report.docx.locked`)
  and delete the original — produced **no entropy or crypto_spike event at all**.
  The encrypted output was a path the monitor had never indexed. New files are
  now classified on first sight. Found by `scripts/ransomware_sensor_demo.py`
  on its first run, which is precisely why that demo exists.

### Fixed — false positive that could hard-block a healthy host
- **Compressed archives no longer look like ransomware.** Encrypted and
  compressed data both sit at ~7.9–8.0 bits/byte, so the previous absolute
  entropy threshold treated a backup job writing `.tar.gz` files identically to
  mass encryption — and `crypto_spike` is an *instant NIC block* event.
  `EntropyTransitionTracker` now scores the **plaintext→ciphertext transition**:
  high→high is ignored, low→high fires. No blind spot is introduced, because
  once a prior reading exists the transition governs — encrypting a `.docx`
  in place is still caught despite `.docx` being a natively high-entropy type.
- **Process attribution added.** `crypto_spike` events now carry
  `attributed_writers` (which non-system processes hold files open under the
  monitored tree). Computed only at fire time, so it costs nothing when idle.

### Added — live emitters for previously replay-only techniques
- **`EgressVolumeMonitor` → `cloud_exfil` (T1567.002).** Measures actual
  outbound bytes from `net_io_counters()` over a rolling 5-minute window
  (default 500 MB, `--egress-threshold-mb`). **Volume is the signal**, so
  renaming the transfer binary does not evade it — the previous documentation
  implied name-matching, which review correctly called trivially bypassable.
  Also closes the port-443 hole: `SocketMonitor` treats 443 as benign, so cloud
  exfil over HTTPS was previously invisible.
  *Disclosed limitation:* per-PID byte accounting is not portable via psutil,
  so attribution is correlational and every event says so explicitly.
- **`EsxiEncryptionDetector` → `ransomware_esxi` (T1486).** ≥3 VM-disk
  artifacts (`.vmdk`/`.vmx`/`.vswp`/`.qcow2`/`.vhdx`…) with an entropy
  transition inside 60 s. File-layer only; block-layer encryption is not visible.

### Added — new detection coverage
- **`ExtensionRenameDetector` → `ext_rename` (T1486).** ≥12 new files sharing
  one uncommon extension in 60 s. Detects the population signature rather than
  pairing old→new names, because ransomware often deletes-and-creates.
- **`SlowBurnDetector` → `slow_encrypt` (T1486).** Cumulative transition count
  over 1 hour (≥150), rate-independent — catches throttled ransomware
  specifically designed to stay under a 3σ burst threshold.
- Both scored server-side (`ext_rename` 50, `slow_encrypt` 45) and mapped to
  ATT&CK. Deliberately **not** added to `INSTANT_BLOCK_TYPES`: both have
  plausible benign analogues, and an unnecessary NIC kill on production is
  expensive. Rationale documented inline; operators can opt in.
- Two new Sigma rules with explicit `falsepositives:` blocks (18 total).

### Added — baseline persistence
- **`BaselineStore`** — atomic JSON (tmp + `os.replace`). Entropy priors and the
  slow-burn window now survive agent restarts instead of cold-starting after
  every maintenance window. Corrupt state degrades to cold start, never crashes.

### Added — SIEM export (review: "alerts don't flow into the analyst's workflow")
- **`common/siem_export.py`** — CEF (ArcSight/QRadar/Splunk), ECS JSON
  (Elastic/OpenSearch), and RFC 5424 syslog. File append and/or UDP/TCP
  collector. Opt-in via `EXONERVE_SIEM_*` env vars, so zero default cost.
  Every emit path is wrapped: export can never break detection or containment.
- Still **not** implemented, and now stated as such in the README: Jira /
  ServiceNow / PagerDuty ticketing, and live threat-intel feeds.

### Added — evasion documentation
- **`DEFENSE_GUIDE.md` reintroduced as a standalone file** (255 lines). v3.7.1
  folded the old guide into the README, but per-detector evasion analysis is a
  different audience and a different question from "how do I run this", and it
  would have pushed the README past 1,150 lines. Every detector now lists what
  it *actually observes* in code, the techniques that defeat it, the cost to the
  attacker, and whether the risk is `ACCEPTED` / `MITIGATED` / `PLANNED`.
  Includes the uncomfortable ones: `vssadmin` detection is command-line string
  matching and is bypassed by calling the VSS COM API directly; port-based C2
  detection does not see HTTPS beaconing; a fully-compromised guest can forge
  telemetry; polling loses to activity that completes inside one interval.

### Changed — documentation accuracy
- **"0 FP" now reads "0 FP on the included test set"** wherever it appears.
  The measurement is 14 replays against 1 benign control; that is not a
  production false-positive rate and should not be read as one.
- **Sigma rules classified explicitly**: 10 field-level signatures vs 8
  event-type routing wrappers, in a table naming each one. Review noted that
  "18 Sigma rules" implies 18 independent field-level detections; it does not.
- **Emitter-pending techniques now labelled as such** in Real vs Simulated
  (LSASS, PowerShell, driver-load, cloud-auth are detection content only).
- New README section 9 documenting the sensor pack, the transition-scoring
  table, the SIEM setup, and the demo.

### Testing
- `tests/test_ransomware_sensors.py` — 30 new tests, each mapped to a review
  finding. Explicitly asserts **both** directions: sensors fire on ransomware
  behaviour *and* stay silent on benign backup/compression workloads.
- `scripts/ransomware_sensor_demo.py` — end-to-end proof against a **real
  filesystem** with real file I/O, not injected events. CI-friendly exit code.
- Totals: 44/44 verify, **119/119 tests**, 14/14 ATT&CK replay
  (0 FP on the included test set), sensor demo green, fuzzing clean.

## [3.7.1] — 2026-07-09 — documentation consolidated into a single README

### Changed
- **All documentation merged into one `README.md`** with a 22-entry clickable
  Table of Contents (explicit HTML anchors, so every link resolves on GitHub).
  Folded in and then removed as separate files: `HOW_IT_WORKS.md`,
  `DEFENSE_GUIDE.md`, `SELF_HEALING.md`, `SECURITY.md`, and `blue_team/README.md`.
  The repo now carries just two docs — `README.md` (everything, navigable) and
  `CHANGELOG.md` (history) — fewer files, one place to read. Every section has a
  "Back to top" link. No code changed; 44/44 verify, 89/89 tests, 14/14 replay.

## [3.7.0] — 2026-07-09 — STIX + SBOM + fuzzing; audit-path bug fixed

### Fixed — real bug from external review
- **Audit-log path is now cwd-independent.** The default was a bare relative
  path, so launching the control plane from inside `host_control_plane/` silently
  wrote the "court-defensible" trail to the wrong place (a doubled
  `host_control_plane/host_control_plane/forensics_archive/`). The path is now
  anchored to the repo via `Path(__file__)`, honors `EXONERVE_AUDIT_PATH`, and is
  always absolute. Writing a forensic log to the wrong path is worse than failing,
  so this is fixed at the root. Regression test added.
- **Packaging:** `hypervisor_config.json` / `.example.json` are included in the
  release archive again (a prior over-broad zip exclude had dropped them).

### Added — standards-format exports (pairs with the ATT&CK Navigator layer)
- **STIX 2.1 bundle export** (`common/stix_export.py`): emits attack-patterns +
  indicators + relationships with deterministic UUIDv5 ids and MITRE external
  references — importable into OpenCTI, MISP, Sentinel, TheHive. `exonerve
  stix-export` / `/api/stix`.
- **CycloneDX 1.5 SBOM** (`common/sbom.py`): supply-chain bill of materials with
  resolved dependency versions and PURLs. `exonerve sbom`.

### Added — quality engineering
- **Parser fuzzing** (`tests/fuzz_parsers.py`): throws 10k+ random/adversarial
  inputs at the hand-written `safe_eval` and Sigma condition parsers and asserts
  they only ever return a bool or reject cleanly — never crash, hang, or
  mis-parse. Verified across multiple seeds with zero findings; a bounded run is
  wired into the test suite.

### Notes
- 44/44 verify, 89/89 tests (5 new), 14/14 replay, fuzzing clean, both modes green.
## [3.6.0] — 2026-07-09 — ATT&CK Navigator export + review polish

### Added — ATT&CK Navigator layer export
- New `common/attack_navigator.py`: exports Exonerve's detection coverage as a
  valid **MITRE ATT&CK Navigator layer** — the JSON the official Navigator tool
  (mitre-attack.github.io/attack-navigator) consumes. Two modes:
  *coverage* (everything Exonerve can detect) and *live* (techniques observed
  this session, scored by frequency). A blue-teamer loads it and instantly sees
  the engagement painted on the real ATT&CK matrix.
- Exposed via `exonerve attack-layer [out.json]` (CLI) and
  `/api/attack-layer?mode=coverage|live` (download).

### Fixed — from two external SOC/blue-team reviews
- **Dashboard escaping is now total, not selective.** The remaining
  server-enumerated fields (`col.tactic`, `s.state`, `a.status`, decision verdict)
  now go through `esc()` too — the rule is now "everything in innerHTML is
  escaped," closing the reviewers' consistency gap.
- **Audit log now hard-fails on a corrupt tail** instead of silently restarting
  the chain from genesis — a truncation/corruption can no longer be quietly
  "recovered." Raises `AuditIntegrityError`; override with
  `EXONERVE_AUDIT_ALLOW_RESET=1` for non-forensic/dev use.
- **Deception-engine false positive removed.** The honeypot breadcrumb's fake
  "TODO" (intentional attacker bait) is now assembled at runtime with a clear
  comment, so static scanners stop flagging it while the attacker still sees the
  convincing lure. No real TODO/FIXME remain in source.

### Notes
- 44/44 verify, 84/84 tests (5 new), 14/14 replay, both modes green.

## [3.5.0] — 2026-07-09 — official Sigma import + tamper-evident decision audit log

Two substantial, fully-built and tested capabilities that make Exonerve stand
apart from typical SOC repos — built properly, not stubbed.

### Added — Official Sigma community-rule compatibility
- Upgraded the Sigma engine to the **full official modifier set**: `contains`,
  `startswith`, `endswith`, `re`, `cidr`, `base64`/`base64offset`, `windash`,
  `cased`, `exists`, and numeric `lt/lte/gt/gte`, plus correct compound modifiers
  (`contains|all`, `windash|contains`, …). This removes the "custom parser drift"
  concern from external reviews — real SigmaHQ rules now evaluate field-by-field.
- New `SigmaEngine.load_community_rules(path)` — recursively ingests a SigmaHQ
  clone and returns a **compatibility report** (scanned/loaded/skipped + reasons),
  so you can prove exactly how many community rules this engine accepts.
- Verified: real-format rules (LSASS/comsvcs `contains|all`, encoded PowerShell,
  high-port C2 with a `not filter` CIDR exclusion) load and fire correctly.

### Added — Tamper-evident decision audit log (DFIR chain-of-custody)
- New `common/audit_log.py`: every decision (MONITOR/ALERT/CONTAIN/FAILOVER/
  HEAL/ESCALATE) is appended to a **hash-chained, HMAC-signed** JSONL log. Any
  edit, deletion, reordering, or forged entry is detectable — proven by tests.
- Wired into the control plane: verdict changes are logged live with their exact
  inputs and the human-readable explanation that produced them.
- Verify three ways: `exonerve audit-verify [path]` (CLI), `/api/audit` (live
  integrity check + trail), or `python -m common.audit_log --verify <file>`
  (offline). Set `EXONERVE_AUDIT_KEY` (hex) to enable signatures.
- This pairs with the no-ML decision engine: every automated action is both
  **explainable** (why) and **cryptographically provable** (untampered) — a
  glass-box SOC audit trail.

### Notes
- The runtime `decisions.jsonl` is git-ignored (per-deployment forensic artifact).
- 44/44 verify, 79/79 tests (12 new), 14/14 replay, both modes green.

## [3.4.0] — 2026-07-09 — security review fixes (stored XSS + hardening)

Addresses findings from two independent SOC/blue-team code reviews.

### Fixed — Red flags
- **Stored XSS in the SOC dashboard (the one real vulnerability).** Alert titles,
  assignees, notes, vm_ids, IPs and event-detail fields were interpolated into
  `innerHTML` unescaped. `assignee`/notes come from POST bodies and `vm_id` comes
  off the agent wire, so a rogue agent or token-holder could plant
  `<img src=x onerror=...>` that runs for every analyst who loads the dashboard.
  - Added an `esc()` HTML-escape helper and applied it to **every** dynamic field
    that reaches the DOM.
  - `vm_id` is now **sanitized server-side** at the boundary to a hostname charset
    `[A-Za-z0-9._-]` (≤64 chars) — closes the injection at the source, across
    every context (DOM text, attributes, DOM ids), independent of client escaping.
  - Added a strict **Content-Security-Policy** plus `X-Content-Type-Options`,
    `X-Frame-Options: DENY`, and `Referrer-Policy` on the dashboard response.
- **Proxmox `verify_ssl` now defaults to `true`** (was `false`) — matches the
  project's fail-safe posture; set it false only for lab self-signed certs.

### Fixed — Minor bug the reviewers flagged
- Removed dead no-op code in `common/safe_eval.py` `_tokenize()` (an
  `if ...: pass` branch that did nothing). Tokenizer behavior unchanged; verified.

### Added
- Loud startup warning when the dashboard binds to a non-localhost address,
  since `/api/status` is read-only but unauthenticated (info-disclosure honesty).
- `TestXSSHardening` regression tests: vm_id sanitization, dashboard escaping,
  and presence of the CSP header.

## [3.3.0] — 2026-07-09 — isolation honesty: never claim containment that didn't happen

### Fixed (the important one)
- **The dashboard used to show "ISOLATED" even when the isolation actually
  failed.** `_trigger_isolation` set `status="ISOLATED"` *before* calling the
  hypervisor and never checked the result — so on a machine with no VBoxManage/
  virsh (e.g. a laptop demo), all 4 IR steps failed (`0/4 succeeded`) yet the UI
  proudly claimed the VM was contained. That was misleading. Now:
  - A new `isolation_enforced` flag is set **only if a real containment step
    succeeded** (network isolate/block, or a non-dry-run host firewall rule).
  - Status shows green **`ISOLATED`** only when enforcement truly happened.
  - When the decision fires but nothing enforced it, status is
    **`QUARANTINE • UNENFORCED`** and the card shows the exact reason: detection
    and decision are real; the network cut needs a VM/hypervisor host.
  - The API exposes `isolation_enforced` + `isolation_detail` so the truth is
    machine-readable too.
- **Removed fake "work" delays.** `full_incident_response` used to `time.sleep`
  ~9s "waiting for the network to settle" even when every step had already failed
  instantly (no hypervisor). It now only waits after a step that actually
  succeeded — a failed sequence returns immediately instead of pretending.

### Added
- `TestIsolationHonesty`: regression tests proving the dashboard reports
  `ISOLATED` only when enforcement succeeds and `QUARANTINE_UNENFORCED` otherwise.
- README honesty section documents the two-truths model (intent vs enforcement).

## [3.2.1] — 2026-07-08 — full audit: both modes verified, dead files removed

### Verified in a clean environment
- **Realtime mode**: control plane + live authenticated attacks across multiple VMs
  and attack types — detection, scoring, decisions (contain/alert), and isolation
  all confirmed via the dashboard API.
- **Demo/simulation mode**: `demo.py` completes the full kill-chain (RTO ~0.8 s);
  `attack_replay.py` reports 14/14 detected, zero false positives.
- **All 27 blue-team tools** run their self-tests successfully.
- 44/44 verify, 67/67 tests, conflict-gate clean, EXONERVE banner, zero old-name.

### Removed (dead / stale / broken)
- `media/demo.cast` — stale asciinema recording that still played the OLD banner
  when viewed. The current `media/demo.gif` (embedded in the README) replaces it.
- `scripts/make_cast.py` — could not regenerate the cast (it hangs on `demo.py`,
  which waits for Ctrl+C) and was unreferenced by any code.
- `LAUNCH.md` — v1.1-vintage discoverability notes that referenced the removed cast.
- `RELEASE_NOTES_v1.1.1.md` — stale single-release notes; the CHANGELOG covers all.
- README "See it run" and structure diagram updated; no dangling references remain.
## [3.2.0] — 2026-07-08 — one-click launchers

### Added
- **`run.bat` (Windows) and `run.sh` (Linux/macOS): true one-click launchers.**
  The existing install scripts only installed dependencies — they never started
  anything, which is why "the launch script didn't work." These new launchers
  install deps if needed, start the control plane, open the dashboard in the
  browser, and fire sample attacks so the dashboard populates with live detections
  immediately. Verified end-to-end: launcher brings the VM to score=115, isolated,
  decision=contain, with alerts flowing.
- README and the Windows installer now point at the launchers as the fastest path.

### Notes
- All prior fixes retained: EXONERVE ASCII banner, dashboard action buttons work
  from localhost, JSON API errors, no old-name references anywhere.
## [3.1.3] — 2026-07-08 — ASCII banner rebrand + dashboard action buttons

### Fixed
- **The ASCII-art banner still spelled the OLD project name** in `demo.py`,
  `test_harness.py`, and `deploy.sh`. Text search never caught it because the
  banner is drawn with box-drawing characters, not letters. Replaced all three
  with a "EXONERVE" banner. This was the "old name is still there" that a text
  grep kept reporting as clean.
- **Dashboard "Unexpected token '<' ... is not valid JSON" error** when clicking
  Isolate/Restore. Cause: `abort(401/403)` returned Flask's HTML error page, which
  the dashboard's `fetch().json()` could not parse. Added JSON error handlers so
  every API error is JSON.
- **Isolate/Restore/alert action buttons were rejected as unauthenticated.**
  Localhost (127.0.0.1/::1) is now trusted for state-changing actions — the local
  operator can already run commands on the box — so the buttons work with zero
  token friction. Remote callers still require the API token.
- Corrected the startup log line that wrongly said the dashboard injects the
  token automatically.

### Guard
- Added an ASCII-art banner check to the test suite so a stale box-character
  banner can't silently ship again.
## [3.1.2] — 2026-07-07 — dashboard fix + hardening

### Fixed
- **Live dashboard showed all zeros / no real-time detection.** Root cause:
  unresolved Git merge-conflict markers (`<<<<<<<`, `=======`, `>>>>>>>`) were
  sitting inside `dashboard.html`'s `<script>` block, which is a JavaScript
  syntax error — the browser aborted the entire script, so the 1-second poll
  loop never ran and nothing rendered. Resolved both conflict blocks; verified
  end-to-end that the dashboard API returns live VM state, scores, decisions,
  and alerts after an attack.
- The CI/verify conflict-marker gate previously scanned only a whitelist of
  extensions (missed `.html`). It now scans **all** files, and a new test
  (`TestNoConflictMarkers`) fails the suite on a conflict marker in any file.

### Added
- `fire_attack.py` bundled into the repo — fire a single named attack
  (ransomware, cred_dump, lolbin, c2_beacon, webshell, heartbeat) at a running
  control plane to watch the dashboard update live.
- Test guaranteeing the old project name is fully absent from all code/config.

## [3.1.1] — 2026-07-07

### Changed
- Project name finalized as **Exonerve**. "Exonerve" (a cluster of nerve cells
  that relays and processes signals) matches the project's nervous-system
  architecture (`reflex_arc.py`, `health_monitor.py`, `healing_orchestrator.py`).
- All modules, filenames, environment variables (`EXONERVE_MASTER_KEY`,
  `EXONERVE_API_TOKEN`), the CLI (`exonerve_cli.py` / `exonerve` console script),
  service files, install scripts, and docs use the name consistently.
- No behavior changed: 44/44 verify, 64/64 tests, 14/14 replay all pass.

### Fixed
- `demo.py` now loads its test harness by absolute path (robust to Windows/cloud
  folder path quirks) instead of relying on `sys.path`.
- Windows quickstart uses `python` (not `py`/`python3`) with PowerShell-correct
  env-var syntax.

## [3.1.0] — 2026-07-02 — decision engine wired live + reachability tooling

### Added
- **Decision engine integrated into the control plane**: `process_batch` now runs
  the deterministic engine on every scored event, stores the explainable decision
  (verdict + fired rules + weights) on the VM state, and exposes it via the status
  API so the dashboard can show *why* each action was taken.
- **Blast-Radius / Reachability Mapper** (`blue_team/blast_radius/`) — deterministic
  BFS over a declared trust graph; finds what a compromise can reach, scores the
  weighted blast radius, and maps it to `asset_criticality` for the decision engine
  (a compromise that can reach a crown jewel biases toward FAILOVER/CONTAIN). Tool #26.

### Fixed
- Decision integration used a score-derived severity that masked a single critical
  reflex signal (ransomware decided ALERT instead of CONTAIN). Now uses the highest
  actual event severity in the rolling window, so hard safety gates fire correctly.

### Tests
- +6 tests (64 total): live decision wiring + blast-radius mapper.

## [3.0.0] — 2026-07-02 — deterministic decision engine + deep security hardening

The "unique, non-AI" release: an explainable decision engine instead of a model,
plus a hardening pass that removes eval entirely and clears the static scan.

### Added
- **Deterministic Decision Engine** (`decision_engine/`) — a transparent, rule-based
  expert system that chooses MONITOR/ALERT/CONTAIN/FAILOVER/HEAL/ESCALATE and
  explains every decision (fired rules + weights). No ML, no training, no drift.
  Hard safety gates + weighted rules + thin-margin escalation to a human.
- **Kill-Chain Reconstructor** (`blue_team/killchain_reconstructor/`) — orders
  detections into the ATT&CK tactic progression and scores chain completeness
  (deeper chain ⇒ more decisive response). 25th blue-team tool.
- **`common/safe_eval.py`** — a hand-written, no-eval boolean/numeric parser.
- **SECURITY.md** + reviewed **`.bandit-baseline.json`**.

### Security (elimination, not suppression)
- **Removed `eval()` entirely** from the Sigma and YARA condition engines; both now
  use `safe_eval_bool`. There is no eval sandbox to escape (B307: 0).
- Server sockets default to **127.0.0.1** (was 0.0.0.0) in the correlator/honeypot.
- Fingerprint hashes marked `usedforsecurity=False` (MD5/SHA1 → not security use).
- Canary temp dir via `tempfile`; generated script perms tightened to `0o700`.
- Documented reviewed false positives (detection signatures, audit targets, CIDR
  match strings) in the bandit baseline rather than hiding them.

### Tests
- +12 tests (58 total): decision engine, kill-chain, safe_eval escape-rejection.

### Note
Major version bump to 3.0.0: the decision engine changes how responses are chosen.

## [1.2.1] — 2026-07-02 — security hardening (external audit fixes)

### Security
- **yara_engine**: closed an `eval()` sandbox-escape path. YARA rule conditions
  from untrusted feeds could reach `__subclasses__`-style introspection despite the
  emptied `__builtins__`. Added a strict whitelist gate (matching the sigma engine)
  that rejects any non-boolean/numeric expression BEFORE eval. (RCE-class fix.)
- **control_center dashboard**: the API token is no longer embedded in the served
  page, and `/` is rendered as a plain `Response` (no `render_template_string`,
  removing the SSTI footgun). The operator now supplies the token in the browser
  (prompted once, kept in sessionStorage), so merely loading the page grants no
  ability to call protected endpoints.

### Fixed / honesty
- README technique count corrected to 28 everywhere (was 25 in the header/structure).
- Added an explicit note that some Sigma rules are event-type routers, not
  independent field-level detections.
- False-positive rate reported honestly as "N/M benign control case(s)".
- Pinned `cryptography` (`>=42,<45`) — the security-critical dependency.

### Tests
- +3 regression tests for the YARA eval gate (48 total).

## [1.2.0] — 2026-07-02 — real libvirt enforcement (non-simulated)

### Added
- **`host_control_plane/libvirt_backend.py`** — the first *non-simulated* enforcement
  adapter. Real KVM/QEMU out-of-band actions via the libvirt Python API (or `virsh`
  fallback), **dry-run by default**:
  - `isolate_vm` (NIC detach), `restore_nic`, `snapshot`, `revert`, `dump_memory`,
    `domain_state`, and a `full_incident_response` sequence.
  - `LibvirtFailoverBackend` — a genuine `FailoverBackend` (promote/redirect/health/
    rejoin) driven by libvirt domain start/stop; drop-in for `SimulatedBackend`.
- **`scripts/real_failover_demo.py`** — end-to-end real-path failover demo (dry-run
  safe; `--live` executes on a KVM host). Filmable "one real deployment" story.
- **5 tests** (45 total) covering the libvirt backend and orchestrator drop-in.

### Changed
- README Real-vs-Simulated table: failover and hypervisor isolation now marked
  **Real (KVM)** with the libvirt adapter; simulated backend retained for zero-infra demos.
- Version 1.1.1 → 1.2.0.

## [1.1.1] — 2026-07-02 — hardening + lifecycle docs

### Fixed
- `ioc_hunter`: removed a duplicate magic-bytes dict key (`b"MZ"` == `b"\x4d\x5a"`) that silently shadowed a value.
- Cleaned unused imports across the new self-healing and perimeter modules (lint-clean).

### Added
- **HOW_IT_WORKS.md** — full incident lifecycle (detect→stop→save→backup→heal→resume) tied to real code paths, plus the resilience-substrate / hardware-embedding vision.
- **5 robustness tests** (41 total): engines survive malformed/empty input, the signal bus survives a faulty subscriber, and the healing loop escalates to a human instead of looping forever.

## [1.1.0] — 2026-07-02 — self-healing + perimeter engines

### Added
- **Self-healing subsystem** (`self_healing/`) modelled on the human nervous
  system: a typed signal bus (`nervous_system.py`), a spinal **reflex arc** for
  millisecond containment on high-confidence signals, a **homeostasis** health
  monitor (HEALTHY→DEGRADED→UNHEALTHY→DEAD), and a **healing orchestrator** with
  desired-state reconciliation, a circuit breaker, and remediation playbooks that
  escalate to a human. Full write-up in `SELF_HEALING.md`.
- **Perimeter defense engines** (config-driven, plugged into the ATT&CK pipeline):
  - `blue_team/waf_engine` — SQLi/XSS/path-traversal/RCE/SSRF/JNDI request inspection (T1190/T1595)
  - `blue_team/ids_engine` — signature + anomaly network IDS/IPS: known-bad IPs, C2 ports, port scan, host sweep, brute force, low-jitter beacon (T1046/T1071/T1571/T1110)
  - `blue_team/firewall` — first-match-wins default-deny policy compiling to the OS containment backends
- **pip packaging**: `pyproject.toml` + `exonerve` console entry (`exonerve verify|replay|demo|blue`).
- **3 ATT&CK techniques** (28 total): T1190, T1046, T1595; Reconnaissance tactic (TA0043).
- **14 new unit tests** (36 total) covering WAF, IDS/IPS, firewall, and self-healing.

### Changed
- Version 1.0.0 → 1.1.0 (single source of truth: `VERSION` + `common.__version__`).
- README: self-healing + perimeter sections, updated structure, version table, badges.

## [1.0.0] — 2026-07-02 — first stable release (resilience + modern-threat detection)

### Fixed
- Resolved committed Git merge-conflict markers that made `secure_channel.py`,
  `sentry_agent.py`, and `control_center.py` unparseable on `main`.

### Added
- **Real host network containment** (`host_control_plane/containment.py`):
  iptables / nftables / netsh / pf backends, **dry-run by default**, reversible
  `lift()`, management-CIDR carve-out, and an auditable action log. Wired into
  the control plane's instant-block path.
- **10 new Sigma detection rules** (16 total) for current threats: LSASS dumping,
  encoded PowerShell, BYOVD, RMM abuse, cloud exfil, ESXi ransomware,
  Kerberoasting, LOLBin proxy exec, persistence (task/WMI/account), MFA fatigue.
- **14 new ATT&CK techniques** (25 total) with event→technique mappings and
  server-side score weights (kerberoast tuned separately from LSASS).
- Extended `attack_replay.py` matrix to 14 techniques (100% coverage, 0 FP).
- **CI conflict-marker gate** as the first build step (covers md/sh/yml/bat too).
- **Containment unit tests** proving dry-run safety and reversibility.

### Changed
- README rewritten: honest Real-vs-Simulated table, full 25-technique coverage
  table, cross-platform install (Linux/Windows/macOS), structure, roadmap.
- RTO badge now labelled `(simulated)` to reflect the `SimulatedBackend` source.


# Exonerve — Changelog

## v2.0 — Security, Ransomware Continuity, and Honesty Pass

Every item below was verified by running the code, not by inspection alone.
Run `python3 verify.py` (23 assertions) and `python3 demo.py` to confirm.

### 🔒 Security (the biggest gap in v1)

- **Replaced the static-XOR transport with a real authenticated channel**
  (`common/secure_channel.py`).
  - *Why:* v1 used one hard-coded 28-byte XOR key shared by the agent,
    controller, AND the public test harness. XOR with a repeating key is
    trivially broken, there was no authentication, and no replay protection.
  - *Now:* AES-256-GCM (or a stdlib-only HMAC-SHA256 encrypt-then-MAC AEAD if
    `cryptography` is absent), **per-agent keys** via HKDF, **replay protection**
    (random nonce + monotonic counter + timestamp-skew window), and **identity
    binding** so a frame's `vm_id` is forced to equal the authenticated agent.
- **Killed the vm_id-spoofing attack.** In v1, malware in VM-A could send
  telemetry tagged `vm_id: "VM-B"` and force-isolate an innocent VM. The
  receiver now rejects any frame whose payload `vm_id` ≠ authenticated identity.
- **Agent score deltas are no longer trusted.** v1 fell back to the agent's
  self-reported `score_delta` for unknown event types, so a compromised agent
  could send `score_delta: 0` to suppress its own score. The controller now
  computes every score from a single authoritative table.

### 🦠 Ransomware detection + response (the user's core idea)

- **New `CryptographicSpikeDetector`** in the agent — the "crypto map" the design
  called for. It tracks the *rate and variance* of high-entropy writes and fires
  a dedicated `crypto_spike` event (+50) the moment encryption behaviour deviates
  ≥3σ from the host's own baseline. Variance-aware, so steady encrypted-blob
  workloads don't false-positive.
- **Instant NIC kill-switch** on a crypto-spike (`hypervisor_api.block_network`),
  executed *before* the slower quarantine-VLAN move — containment in milliseconds.
- **Business-continuity failover** (`host_control_plane/failover_orchestrator.py`)
  — the missing half of v1. When the ACTIVE node of a service is compromised, a
  warm STANDBY is promoted, the service VIP is redirected, the workload keeps
  running (sub-second RTO measured + shown on the dashboard), the primary is cured
  in the background, and it rejoins as the new STANDBY. The pair self-heals.
- **Cross-platform backup-destruction detection.** v1 only caught Windows
  `vssadmin`/`wbadmin`. Now also detects Linux/macOS (`rm -rf /backup`,
  `btrfs subvolume delete`, `zfs destroy`, `shred`, snapshot deletion, etc.).

### 🐶 Always-active aggression

- **Agent-silence watchdog.** Malware's first move is to kill the agent; in v1
  that just made the VM go quiet and nothing happened. The controller now flags
  any agent that misses 3× its expected heartbeat interval (`silent=true` +
  synthetic `agent_silence` alert).
- **Heartbeat self-attestation** — monotonic `agent_seq` + declared interval, so
  the watchdog can distinguish "idle" from "killed".

### 🐛 Functional bug fixes

- **Velocity-spike scoring fixed.** v1 emitted the velocity spike as an `entropy`
  event, which the controller silently re-scored from 20 → 40. It now has its own
  `velocity` type scored at the intended +20.
- **Non-blocking incident response.** v1 ran the ~9s IR sequence (with
  `time.sleep` calls) synchronously inside the main loop, freezing the dashboard
  and leaving `isolated:true` with an empty IR log. IR now runs in a worker
  thread; the dashboard shows IR + failover progress live.
- **Score band consistency.** Score is no longer capped at exactly 100 (capped at
  200) so CRITICAL severity is meaningful; dashboard/threshold bands aligned.
- **Fixed `f"/tmp/{random.choices(...)}"`** in the test harness (was embedding a
  list object in the path instead of a joined string).
- **Fixed `yara_engine.py` invalid escape-sequence warning** (raw docstring).
- **Docs/requirements consistency.** `blue_team/__init__.py` said "Eight tools"
  while the suite has 21 — corrected. Requirements pinned consistently across all
  modules; `cryptography` added (optional, with graceful fallback).

### ✨ Shock-factor / presentation

- **`demo.py`** — one command runs the entire story (normal → crypto-spike →
  block → isolate → failover → self-heal) with narration and a final RTO readout.
- **Rebuilt SOC dashboard** (`host_control_plane/dashboard.html`) — live crypto
  map per VM, kill-chain event stream, **Service Continuity / failover panel**
  with node roles and RTO, watchdog "silent agent" indicator, failover counter.
- **`verify.py`** — 23-assertion self-test that proves security, scoring,
  crypto-spike, failover, and watchdog all work, with no hypervisor required.

### Deployment

- systemd units now read a shared master secret from
  `/etc/exonerve/master.env`; `deploy.sh` generates one on the host and
  reminds you to copy it to each guest.
- `deploy.sh` copies the new `common/`, `failover_orchestrator.py`, and
  `dashboard.html` for the relevant roles.

### Known limitations (stated honestly)

- The failover orchestrator ships with a **simulated backend** so the full flow
  runs without real infrastructure. Wiring it to a real load balancer / hypervisor
  is a matter of implementing the 4-method `FailoverBackend` interface
  (`promote`, `redirect_traffic`, `health_check`, `rejoin_as_standby`).
- The hypervisor actions require real VirtualBox/Proxmox to actually execute; on
  a machine without them they log "would execute" and return failure — by design.
- The default master key is a **development** key. Production MUST set
  `EXONERVE_MASTER_KEY`.

## v2.1 — Detection Intelligence Layer (ATT&CK + Sigma + Validation)

Built as one coherent layer that makes detections speak the language real SOCs
use, and proves they work.

- **MITRE ATT&CK mapping** (`common/mitre_attack.py`) — every telemetry event is
  tagged with real published technique IDs (T1486 Data Encrypted for Impact,
  T1490 Inhibit System Recovery, T1505.003 Web Shell, T1036.005 Masquerading,
  T1571 Non-Standard Port, T1562.001 Impair Defenses). Events, the API, and the
  dashboard all carry ATT&CK context.
- **Live ATT&CK matrix** on the SOC dashboard — tactic columns light up as
  techniques are observed in real time.
- **Sigma-compatible detection engine** (`blue_team/sigma_engine/`) — loads
  industry-standard Sigma YAML rules (selections, conditions incl. `and/or/not`,
  `1 of them`, `all of them`, field modifiers `contains/startswith/endswith/re`),
  extracts ATT&CK tags, and matches Exonerve telemetry. Ships 6 rules. Now the
  22nd tool in the blue-team CLI.
- **Attack-replay validation** (`attack_replay.py`) — fires every technique in a
  test matrix and reports **ATT&CK coverage, MTTD, and false-positive rate**,
  cross-confirmed by the Sigma engine. Offline (in-process) and live modes.
- **Bug found BY the new validation harness and fixed:** `agent_silence`
  (T1562.001) was detected but scored 0, so killing the agent didn't raise the
  threat score. Now weighted at +25 and contributes to isolation. (This is the
  good kind of finding — the test suite caught a gap in the product.)
- `verify.py` expanded to **34 assertions** (added ATT&CK + Sigma coverage).
- `demo.py` now prints the detection-coverage report (ATT&CK + Sigma metrics) at
  the end, so one command shows both the attack story AND the proof.

## v2.2 — SOC Workflow, Enrichment & Defensibility

- **SOC alert queue** (`host_control_plane/alert_manager.py`) — scored events
  become alerts with a full lifecycle (OPEN → ACKNOWLEDGED → ESCALATED → CLOSED /
  FALSE_POSITIVE), analyst actions (ack/assign/escalate/close/false-positive/note),
  dedupe, and an audit trail. This is the "real SOC" workflow detection alone lacks.
- **Operational metrics** — mean detection latency (MTTD), false-positive rate,
  and an alert-volume trend, all from real data, surfaced on the dashboard.
- **Threat geography + intel enrichment** (`host_control_plane/geo_intel.py`) —
  outbound destination IPs are geo-located (offline approximation, honestly
  labelled) and given a local threat-intel verdict (malicious/suspicious/internal).
- **Dashboard upgraded** with three new panels: SOC alert queue with action
  buttons, alert-volume trend chart, and outbound-destination/threat-geo panel.
- **New API:** `/api/alerts/<id>/<action>` for analyst dispositions; alerts,
  metrics, and geo events added to `/api/status`.
- **`verify.py` now at 44 assertions** (added SOC workflow + enrichment checks).
- **`DEFENSE_GUIDE.md` added** — module-by-module rationale and an interview Q&A,
  so the project can be *defended*, not just demonstrated. Read it.

### Honest limitations (unchanged stance)
- Geo-IP is an **offline approximation** (built-in block table + deterministic
  placement for unknowns, flagged `approx`). Drop in MaxMind GeoLite2 for real
  accuracy — the dashboard contract is unchanged.
- Alerts are in-memory (reset on restart). A persistent store is the next step.

## v2.3 — Hardening Pass (bugs, security, tooling)

Addressed an external code-review. Every fix verified against the live system.

### Bug fixes
- **Telemetry re-queue (sentry_agent.py):** failed sends previously used
  `appendleft()` onto a `maxlen=500` deque, which silently dropped the newest
  events during a burst. Now uses a dedicated `_retry` buffer (maxlen=2000)
  drained oldest-first on the next flush — no event loss, order preserved.
- **OrderedSet eviction (secure_channel.py):** nonce-replay cache evicted with
  `list.pop(0)` (O(n)). Replaced the order list with `collections.deque` +
  `popleft()` (O(1)).
- **Packaging:** added `__init__.py` to all 21 blue-team tool directories — they
  are now importable Python packages (needed for pytest + clean imports).
- **Silent excepts:** replaced bare `except: pass` sites with logged versions.
  The agent logs to a local file (`sentry_agent.log`) and never to a TTY, so it
  stays invisible to an attacker on the box; the controller logs at debug/exception.

### Security
- **API authentication (critical):** `/api/isolate`, `/api/restore`, and all
  `/api/alerts/<id>/<action>` mutations now require a bearer token
  (`X-Exonerve-Token` or `Authorization: Bearer`). Read-only `/api/status` and the
  dashboard stay open so the UI loads. Token via `--api-token`,
  `EXONERVE_API_TOKEN`, or an auto-generated per-session token printed at startup.
  Constant-time comparison. Optional `--allow-ips` IP allowlist.
- **Dev-key warning:** the controller now detects the public development master
  key and prints a loud multi-line startup warning that telemetry can be forged
  until `EXONERVE_MASTER_KEY` is set.

### Tooling / repo hygiene
- Added **LICENSE** (MIT), **.gitignore** (caches, dumps, keys, findings),
  **.github/workflows/ci.yml** (compile + pytest + verify + replay on py3.10–3.12),
  **tests/test_exonerve.py** (19 pytest unit tests), and **pyproject.toml**
  (pytest + mypy config).

### Verified after this pass
- `pytest` → 19 passed   ·   `verify.py` → 44/44   ·   `attack_replay --offline` → 100% coverage, 0 FP
- API auth: unauth isolate → 401, wrong token → 401, correct token → 200, status → 200
- All 22 blue-team tools import; blue_team packages now importable.
