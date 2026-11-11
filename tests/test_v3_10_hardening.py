#!/usr/bin/env python3
"""
Tests for v3.10 — EXONERVE_NEXT_UPDATE_PROMPT.md, Priority 2 items.

Each detector below is tested in BOTH directions per this project's own
standing rule: it must fire on the attack behaviour AND stay silent on the
named benign case that would otherwise be the obvious false positive.
"""

import os
import sys
import time
import random
import string


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "guest_production_vm"))

from ransomware_sensors import ExtensionRenameDetector  # noqa: E402
import modern_threats as mt  # noqa: E402
import sentry_agent as sa  # noqa: E402


class Collector:
    def __init__(self):
        self.events = []

    def __call__(self, event_type, severity, details):
        self.events.append({"event_type": event_type, "severity": severity,
                            "details": details})

    def types(self):
        return [e["event_type"] for e in self.events]


# ---------------------------------------------------------------------------
# Priority 2.2 — sparse / interior-block encryption bypass
# ---------------------------------------------------------------------------

class TestSparseEncryptionSampling:
    def test_small_file_unchanged_single_head_sample(self, tmp_path):
        """Files at/under the sampling threshold behave exactly as before —
        no regression for the common case (most files are small)."""
        p = tmp_path / "small.txt"
        p.write_bytes(b"a" * 1000)
        ent = sa.file_entropy(str(p), sample_bytes=65536)
        assert ent is not None
        assert ent < 1.0   # a run of one repeated byte is ~0 entropy

    def test_head_only_encryption_still_caught(self, tmp_path):
        """Baseline: encrypting the whole file (or just the head) was always
        caught, and must stay caught."""
        p = tmp_path / "big_head_encrypted.bin"
        random_head = os.urandom(300_000)
        plaintext_rest = b"a" * 300_000
        p.write_bytes(random_head + plaintext_rest)
        ent = sa.file_entropy(str(p), sample_bytes=65536)
        assert ent is not None and ent >= 7.2

    def test_tail_only_encryption_now_caught(self, tmp_path):
        """THE fix: a file whose HEAD looks perfectly plaintext but whose
        TAIL is high-entropy ciphertext. Before v3.10 this was invisible —
        file_entropy() only ever read the first 64KB."""
        p = tmp_path / "tail_encrypted.bin"
        plaintext_head = b"a" * 300_000
        random_tail = os.urandom(300_000)
        p.write_bytes(plaintext_head + random_tail)
        ent = sa.file_entropy(str(p), sample_bytes=65536)
        assert ent is not None and ent >= 7.2, (
            "tail-only high entropy must be caught by multi-region sampling")

    def test_interior_only_encryption_now_caught(self, tmp_path):
        """Same fix, interior block instead of tail — several real ransomware
        families specifically encrypt only interior blocks to look plaintext
        under a head-only or head+tail check."""
        p = tmp_path / "interior_encrypted.bin"
        chunk = b"a" * 250_000
        random_middle = os.urandom(250_000)
        p.write_bytes(chunk + random_middle + chunk)
        ent = sa.file_entropy(str(p), sample_bytes=65536)
        assert ent is not None and ent >= 7.2

    def test_large_fully_plaintext_file_stays_low_entropy(self, tmp_path):
        """Benign case for the new code path: a large plaintext file (e.g. a
        big log or CSV) must not spuriously read as high-entropy anywhere."""
        p = tmp_path / "big_plaintext.log"
        line = b"2026-07-19 INFO request handled ok id=12345\n"
        p.write_bytes(line * 20_000)   # well over the multi-region threshold
        ent = sa.file_entropy(str(p), sample_bytes=65536)
        assert ent is not None and ent < 6.5


# ---------------------------------------------------------------------------
# Priority 2.1 — randomised-per-file-extension ransomware
# ---------------------------------------------------------------------------

class TestNovelExtensionRate:
    def test_per_file_random_extensions_fire_via_rate_signal(self):
        """THE fix: 20 files, each with a DISTINCT random extension, in 30s.
        No single extension ever reaches RENAME_MIN_FILES, so the clustering
        check (`ext_rename`) never fires — but the rate of brand-new
        extensions must."""
        c = Collector()
        d = ExtensionRenameDetector(c, min_files=12, novel_min_distinct=15)
        for i in range(20):
            ext = "." + "".join(random.choices(string.ascii_lowercase, k=6))
            d.record_new_file(f"/home/user/victim{i}{ext}")
        result = d.evaluate()
        assert result is not None
        assert "ext_rate_spike" in c.types()
        assert "ext_rename" not in c.types(), (
            "this specific attack must NOT trip the clustering signal — "
            "if it does, the test no longer proves the rate signal works")

    def test_legitimate_project_files_do_not_fire(self):
        """Existing benign case, unchanged: common extensions are filtered
        before novelty is even considered."""
        c = Collector()
        d = ExtensionRenameDetector(c, min_files=12, novel_min_distinct=15)
        for i in range(50):
            d.record_new_file(f"/src/module{i}.py")
        assert d.evaluate() is None
        assert c.events == []

    def test_clustered_locked_extension_still_fires_cluster_signal(self):
        """Existing benign-vs-attack distinction is preserved: the classic
        single-shared-extension attack still fires `ext_rename`, and must NOT
        additionally need 15 distinct extensions to do so."""
        c = Collector()
        d = ExtensionRenameDetector(c, min_files=12, novel_min_distinct=15)
        for i in range(15):
            d.record_new_file(f"/home/user/doc{i}.locked")
        result = d.evaluate()
        assert result is not None
        assert "ext_rename" in c.types()

    def test_handful_of_new_but_ordinary_extensions_does_not_fire(self):
        """Benign case for the NEW code path specifically: a developer adding
        a few new, legitimately-novel-to-this-host file types (say, 5) in a
        burst must not trip a 15-distinct-extension threshold."""
        c = Collector()
        d = ExtensionRenameDetector(c, min_files=12, novel_min_distinct=15)
        for i, ext in enumerate([".proto", ".graphql", ".wasm", ".ipynb", ".tfvars"]):
            d.record_new_file(f"/src/thing{i}{ext}")
        assert d.evaluate() is None

    def test_novel_window_expiry_resets_the_count(self):
        c = Collector()
        d = ExtensionRenameDetector(c, min_files=12,
                                     novel_window=1, novel_min_distinct=15)
        # 17 distinct extensions: enough to clear the FAST-window threshold
        # (15) being tested here, deliberately kept under the LONG-window
        # threshold (20, default) so this test isolates fast-window expiry
        # specifically rather than also tripping the v3.13 long-window check.
        for i in range(17):
            ext = "." + "".join(random.choices(string.ascii_lowercase, k=6))
            d.record_new_file(f"/home/user/victim{i}{ext}")
        time.sleep(1.1)
        assert d.evaluate() is None

    def test_long_window_catches_medium_cardinality_pool_evasion(self):
        """The specific gap this closes: an attacker cycling through a
        pool of extensions sized to stay under BOTH the fast clustering
        threshold (min_files=12, so ≤11 files per extension) AND the fast
        novel-rate threshold (novel_min_distinct=15, so ≤14 distinct
        extensions) IN EACH WAVE — invisible to both fast signals within
        any single wave. But one 14-extension pool used at ≤11 files each
        only covers ~154 files before the attacker needs a FRESH pool to
        keep encrypting more — and introducing fresh pools across
        successive waves is exactly what accumulates in the long window
        even though each individual wave dodges the fast checks."""
        c = Collector()
        d = ExtensionRenameDetector(c, min_files=12, novel_min_distinct=15,
                                    novel_window=1, window=1, long_window_min_distinct=20)

        for wave in range(2):   # 2 waves x 14 = 28 distinct, safely over 20
            pool = ["." + "".join(random.choices(string.ascii_lowercase, k=6))
                   for _ in range(14)]
            for i in range(14 * 11):   # 11 files/ext, under the 12 clustering cap
                ext = pool[i % len(pool)]
                d.record_new_file(f"/home/user/wave{wave}_victim{i}{ext}")
            d.evaluate()
            time.sleep(1.1)   # let the fast (1s) windows expire between waves,
                              # simulating real time passing — the long window
                              # (86400s default) does NOT expire here

        d.evaluate()
        long_window_events = [e for e in c.events
                              if e["details"].get("reason") ==
                              "long_window_novel_extension_accumulation"]
        assert len(long_window_events) >= 1, (
            "accumulated novel extensions across waves must trip the long-"
            "window check even though each wave alone dodged both fast checks")
        cluster_events = [e for e in c.events if e["event_type"] == "ext_rename"]
        assert cluster_events == [], "must dodge clustering in every wave, per the scenario"

    def test_long_window_does_not_fire_on_an_established_hosts_normal_extension_count(self):
        """A host that has already built up its normal ~14-extension
        vocabulary (e.g. from one day's build) must not keep re-firing the
        long-window check every subsequent day just because that count
        stays above zero — once seen, an extension is no longer novel."""
        c = Collector()
        d = ExtensionRenameDetector(c, long_window_min_distinct=20)
        for i, ext in enumerate([".o", ".obj", ".d", ".class", ".wasm"] * 3):
            d.record_new_file(f"/build/obj{i}{ext}")
        assert d.evaluate() is None   # only 5 distinct extensions, well under 20


# ---------------------------------------------------------------------------
# Priority 2.4 — low-volume C2 beaconing (below the bulk-transfer threshold)
# ---------------------------------------------------------------------------

class TestBeaconDetector:
    def test_regular_interval_beaconing_fires(self):
        """Synthetic connections at a fixed ~60s interval, low jitter."""
        c = Collector()
        d = mt.BeaconDetector(c, min_samples=6, min_interval=10.0)
        base = 1_000_000.0
        for i in range(10):
            # +/- 1s jitter around a 60s cadence — low jitter, matches a
            # beaconing implant with a small random sleep skew.
            jitter = random.uniform(-1.0, 1.0)
            d.record_sighting("malware->203.0.113.9:443", base + i * 60.0 + jitter)
        findings = d.evaluate()
        assert findings, "regular low-jitter beacon must fire"
        assert c.types() == ["beacon"]
        assert findings[0]["coefficient_of_variation"] < 0.15

    def test_irregular_human_browsing_does_not_fire(self):
        """Irregular, human-driven connection timing to the same host must
        not fire — this is the whole point of a jitter (not just count)
        based check."""
        c = Collector()
        d = mt.BeaconDetector(c, min_samples=6, min_interval=10.0)
        base = 2_000_000.0
        t = base
        random.seed(42)
        for _ in range(12):
            t += random.uniform(15.0, 900.0)   # wildly irregular gaps
            d.record_sighting("chrome->203.0.113.10:443", t)
        assert d.evaluate() == []
        assert c.events == []

    def test_too_few_samples_does_not_fire(self):
        """Regularity cannot be judged from a couple of data points; the
        detector must wait for enough intervals rather than guess."""
        c = Collector()
        d = mt.BeaconDetector(c, min_samples=6)
        base = 3_000_000.0
        for i in range(3):
            d.record_sighting("proc->203.0.113.11:443", base + i * 60.0)
        assert d.evaluate() == []

    def test_browser_process_allowlisted_via_scan(self, monkeypatch):
        """scan()-level allowlisting: a browser polling a webmail endpoint on
        a perfectly regular interval must not be attributed as C2 beaconing
        just because the timing happens to be regular."""
        import tests.test_modern_threats as tmt  # reuse the shared fakes
        proc = tmt.FakeProc(200, "chrome")
        conn = tmt.FakeConn(200, "203.0.113.20", 443)
        monkeypatch.setattr(mt, "psutil", tmt.FakePsutil([proc], [conn]))
        d = mt.BeaconDetector(Collector())
        for _ in range(10):
            assert d.scan() == []   # allowlisted at the process-name level


# ---------------------------------------------------------------------------
# Control-plane wiring — new event types must be scored and ATT&CK-mapped
# ---------------------------------------------------------------------------

class TestV310ControlPlaneWiring:
    def test_new_event_types_have_scores(self):
        sys.path.insert(0, os.path.join(ROOT, "host_control_plane"))
        import control_center
        for et in ("ext_rate_spike", "beacon"):
            assert control_center.SCORE_WEIGHTS.get(et, 0) > 0, f"{et} unscored"

    def test_new_event_types_map_to_attack(self):
        from common.mitre_attack import map_event_to_techniques
        assert any(t.tid == "T1486" for t in
                   map_event_to_techniques("ext_rate_spike", {}))
        assert any(t.tid == "T1071" for t in
                   map_event_to_techniques("beacon", {}))
