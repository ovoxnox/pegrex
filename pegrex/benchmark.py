"""
benchmark — deterministic agent-edit benchmark

Corpus of (before, after, expected-verdict) agent edits scored by
verify_patch. Metrics: accept-rate on known-good, FALSE-ACCEPT rate
on known-bad (must be 0), determinism (two runs identical).
A verifier that accepts everything scores 0 -- the benchmark refuses
to flatter."""

from __future__ import annotations

import os
import tempfile

from .semantics import verify_patch

B = chr(10)
BASE = B.join(["def classify(n):", "    if n > 0:", "        return 1",
               "    return -1", ""])
ABSVAL = B.join(["def absval(n):", "    if n >= 0:", "        return n",
                 "    return -n", ""])

CASES = [
    {"name": "comment-only", "before": BASE,
     "after": BASE.replace("def classify",
                           "# sign classifier" + chr(10) + "def classify"),
     "expect": True},
    {"name": "dead-statement", "before": BASE,
     "after": BASE.replace("    if n > 0:",
                           "    _ = n" + chr(10) + "    if n > 0:"),
     "expect": True},
    {"name": "swap-branches", "before": BASE,
     "after": BASE.replace("return 1", "return -1")
                    .replace("    return -1" + chr(10), "    return 1" + chr(10)),
     "expect": False},
    {"name": "constant-fold-wrong", "before": BASE,
     "after": B.join(["def classify(n):", "    return 1", ""]),
     "expect": False},
    {"name": "absval-equiv", "before": ABSVAL,
     "after": B.join(["def absval(n):", "    if n < 0:", "        return -n",
                      "    return n", ""]),
     "expect": True},
    {"name": "absval-broken", "before": ABSVAL,
     "after": ABSVAL.replace("return -n", "return n"),
     "expect": False},
]


def run_case(case, verifier=None):
    """Implement run case with the module's explicit API and failure semantics."""
    verifier = verifier or verify_patch
    tmp = tempfile.mkdtemp()
    a = os.path.join(tmp, "a.py")
    b = os.path.join(tmp, "b.py")
    open(a, "w", encoding="utf-8").write(case["before"])
    open(b, "w", encoding="utf-8").write(case["after"])
    try:
        out = verifier(a, b)
        return {"name": case["name"],
                "verified": bool(out.get("verified")),
                "expected": case["expect"],
                "correct": bool(out.get("verified")) == case["expect"],
                "counterexample": (out.get("counterexample") or {}).get("inputs")}
    except Exception as e:
        return {"name": case["name"], "verified": None,
                "expected": case["expect"], "correct": False,
                "error": f"{type(e).__name__}: {e}"[:160]}


def run_benchmark(verifier=None, cases=None) -> dict:
    """Implement run benchmark with the module's explicit API and failure semantics."""
    results = [run_case(c, verifier) for c in (cases or CASES)]
    good = [r for r in results if r["expected"]]
    bad = [r for r in results if not r["expected"]]
    accepts_good = sum(1 for r in good if r["verified"] is True)
    false_accepts = sum(1 for r in bad if r["verified"] is True)
    return {
        "cases": len(results),
        "correct": sum(1 for r in results if r["correct"]),
        "accept_rate_good": round(accepts_good / max(len(good), 1), 3),
        "false_accept_rate": round(false_accepts / max(len(bad), 1), 3),
        "score": round(sum(1 for r in results if r["correct"]) / max(len(results), 1), 3),
        "results": results,
    }
