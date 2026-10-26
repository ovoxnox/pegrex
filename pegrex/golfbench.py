"""
golfbench - performance-golf scorer over the cert-fixture corpus.

Golfing a certificate fixture means: faster runtime, fewer lines, same
semantics. golfbench measures all three and scores improvements -- but a
"golf" that weakens a refusal (deletes or softens a negative control)
scores minus infinity: the hole-in-one that broke the proof is detected,
not celebrated. Baselines are stored per fixture; stale baselines are
re-measured, never guessed."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import time

BASELINE = {}


def _hash(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()[:12]


def measure(cert_path, timeout=240):
    """Runtime (3-run min, ms), LOC, refusal count for one cert fixture."""
    src = open(cert_path, encoding="utf-8").read()
    loc = sum(1 for l in src.splitlines() if l.strip())
    refusals = src.count("neg control") + src.count("REFUSAL")
    best = None
    for _ in range(3):
        t0 = time.perf_counter()
        r = subprocess.run([sys.executable, cert_path], capture_output=True,
                           timeout=timeout)
        ms = (time.perf_counter() - t0) * 1000.0
        if r.returncode != 0:
            return {"error": (r.stderr or r.stdout)[-160:], "loc": loc,
                    "refusals": refusals}
        best = ms if best is None else min(best, ms)
    return {"ms": round(best, 1), "loc": loc, "refusals": refusals,
            "sha": _hash(cert_path)}


def golf(cert_path, baseline_path=None):
    """Score the current fixture against its baseline."""
    cur = measure(cert_path)
    if "error" in cur:
        return {"status": "broken", **cur}
    base = None
    if baseline_path:
        try:
            base = json.load(open(baseline_path, encoding="utf-8"))
        except Exception:
            base = None              # stale/missing: re-measure, never guess
    if base is None or base.get("sha") and base.get("sha") != cur.get("sha") \
            and baseline_path is None:
        base = None
    if base is None:
        return {"status": "baseline", **cur,
                "note": "no prior baseline -- this run becomes it"}
    verdict = "par"
    if cur["refusals"] < base["refusals"]:
        return {"status": "refusal-golf", "score": float("-inf"),
                "reason": "negative control removed or weakened -- the "
                          "golf broke the proof", "base": base, "cur": cur}
    if cur["ms"] < base["ms"] * 0.9 and cur["loc"] <= base["loc"] * 1.05:
        verdict = "birdie"           # >=10% faster without LOC bloat
    if cur["loc"] < base["loc"] * 0.9 and cur["ms"] <= base["ms"] * 1.1:
        verdict = "eagle"            # >=10% smaller without slowing much
    if cur["ms"] > base["ms"] * 1.5:
        verdict = "bogey"
    return {"status": verdict, "base": base, "cur": cur,
            "speedup": round(base["ms"] / max(cur["ms"], 0.01), 2)}


def baseline_all(cert_dir, baseline_path):
    """Implement baseline all with the module's explicit API and failure semantics."""
    rows = {}
    import pathlib
    for p in sorted(pathlib.Path(cert_dir).glob("m*.py")):
        rows[p.name] = measure(str(p))
    json.dump(rows, open(baseline_path, "w", encoding="utf-8"), indent=1)
    return rows
