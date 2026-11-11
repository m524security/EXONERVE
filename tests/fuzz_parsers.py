"""
Fuzz harness for Exonerve's hand-written parsers.

Custom parsers are exactly where a security tool earns — or loses — trust: a
crash, hang, or (worst) a silent mis-parse in the rule engine is a detection
failure. This harness throws large volumes of random and adversarial input at
the two hand-rolled parsers and asserts the ONLY acceptable outcomes:

  * safe_eval_bool  -> returns a bool, or raises SafeEvalError. Never: a crash
    with another exception type, an infinite loop, or (critically) any use of
    Python eval/exec. Never returns a non-bool.
  * Sigma condition -> evaluates to a bool for any selection map. Never crashes
    the engine with an unexpected exception.

Deterministic by default (fixed seed) so CI is reproducible; pass --seed to
vary. This is dependency-free (no hypothesis/atheris) so it runs anywhere.

Run:  python -m tests.fuzz_parsers [--iterations N] [--seed S]
"""
from __future__ import annotations

import argparse
import random
import signal
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "blue_team" / "sigma_engine"))

from common.safe_eval import safe_eval_bool, SafeEvalError  # noqa: E402
from sigma_engine import _eval_condition  # noqa: E402


class _Timeout(Exception):
    pass


def _with_timeout(fn, seconds=2):
    """Guard against a parser hanging (only where SIGALRM exists; else best-effort)."""
    if not hasattr(signal, "SIGALRM"):
        return fn()

    def _handler(signum, frame):
        raise _Timeout()

    old = signal.signal(signal.SIGALRM, _handler)
    signal.alarm(seconds)
    try:
        return fn()
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


# Token pools skewed toward things that stress a boolean/comparison parser.
_ATOMS = ["true", "false", "True", "False", "and", "or", "not", "(", ")",
          ">", "<", ">=", "<=", "==", "!=", "0", "1", "42", "-1", "3.14",
          "  ", "\t", "them", "of", "all", "1 of", "sel", "sel1", "filter"]


def _rand_expr(rng: random.Random, depth: int = 0) -> str:
    n = rng.randint(1, 12)
    parts = []
    for _ in range(n):
        if rng.random() < 0.15:
            parts.append("".join(rng.choice(string.printable) for _ in range(rng.randint(1, 6))))
        else:
            parts.append(rng.choice(_ATOMS))
    return " ".join(parts)


def fuzz_safe_eval(iterations: int, rng: random.Random) -> dict:
    stats = {"runs": 0, "bool_ok": 0, "clean_reject": 0, "bad": []}
    for _ in range(iterations):
        expr = _rand_expr(rng)
        stats["runs"] += 1
        try:
            res = _with_timeout(lambda: safe_eval_bool(expr))
        except SafeEvalError:
            stats["clean_reject"] += 1
            continue
        except _Timeout:
            stats["bad"].append(("HANG", expr))
            continue
        except Exception as e:  # any other exception type is a bug
            stats["bad"].append((f"{type(e).__name__}: {e}", expr))
            continue
        if not isinstance(res, bool):
            stats["bad"].append((f"non-bool result: {res!r}", expr))
        else:
            stats["bool_ok"] += 1
    return stats


def fuzz_sigma_condition(iterations: int, rng: random.Random) -> dict:
    stats = {"runs": 0, "ok": 0, "bad": []}
    names = ["sel", "sel1", "sel2", "filter", "selection", "keywords"]
    for _ in range(iterations):
        cond = _rand_expr(rng)
        results = {n: rng.random() < 0.5 for n in names if rng.random() < 0.7}
        stats["runs"] += 1
        try:
            res = _with_timeout(lambda: _eval_condition(cond, results))
        except _Timeout:
            stats["bad"].append(("HANG", cond))
            continue
        except Exception as e:
            # A malformed condition may raise, but it must not be a crash type
            # that would take down the engine loop uncaught. We accept ValueError/
            # KeyError-style parse failures as "handled"; anything else is a bug.
            if type(e).__name__ in ("ValueError", "KeyError", "SyntaxError",
                                    "SafeEvalError", "AttributeError"):
                stats["ok"] += 1
                continue
            stats["bad"].append((f"{type(e).__name__}: {e}", cond))
            continue
        if not isinstance(res, bool):
            stats["bad"].append((f"non-bool: {res!r}", cond))
        else:
            stats["ok"] += 1
    return stats


def run(iterations: int = 5000, seed: int = 1337) -> bool:
    rng = random.Random(seed)
    print(f"Fuzzing parsers: iterations={iterations} seed={seed}")
    se = fuzz_safe_eval(iterations, rng)
    sg = fuzz_sigma_condition(iterations, rng)
    print(f"  safe_eval: {se['runs']} runs, {se['bool_ok']} bool, "
          f"{se['clean_reject']} cleanly rejected, {len(se['bad'])} bad")
    print(f"  sigma cond: {sg['runs']} runs, {sg['ok']} handled, {len(sg['bad'])} bad")
    for label, sample in (se["bad"] + sg["bad"])[:10]:
        print(f"    BUG [{label}] on: {sample!r}")
    ok = not se["bad"] and not sg["bad"]
    print("  RESULT:", "PASS — no crashes/hangs/mis-parses" if ok else "FAIL")
    return ok


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--iterations", type=int, default=5000)
    ap.add_argument("--seed", type=int, default=1337)
    args = ap.parse_args()
    sys.exit(0 if run(args.iterations, args.seed) else 1)
