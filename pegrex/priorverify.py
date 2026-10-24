"""
priorverify - probabilistic deadline allocation.

Path frequencies decide which paths get verified first inside the
deadline; the result carries coverage -- how much of observed production
traffic the verdict actually covers. A verdict over 40% of traffic says so. 
Silence about coverage is the bug this kills.
"""

from __future__ import annotations

from .probpath import fit as prob_fit, prioritize


def coverage(fitted, verified_results):
    """coverage(fitted, verified_results): see module docstring."""
    total = fitted["total_runs"] or 1
    covered = sum(r["count"] for r in fitted["paths"]
                  if verified_results.get(tuple(sorted(r["constraints"])))
                  in ("proved", "refuted"))
    return round(covered / total, 4)


def verify_under_budget(contracts, traces, check_path, deadline_ms):
    """check_path(path_constraints) -> 'proved'|'refuted'|'unknown'.
    Hot paths first; stops at the deadline; reports coverage."""
    import time
    fitted = prob_fit(contracts, traces)
    ranked = prioritize(fitted)
    results, t0 = {}, time.perf_counter()
    for row in ranked:
        if (time.perf_counter() - t0) * 1000.0 > deadline_ms:
            break
        key = tuple(sorted(row["constraints"]))
        try:
            v = check_path(row["constraints"])
        except Exception:
            v = "unknown"
        # a decision delivered after the deadline does not count
        if (time.perf_counter() - t0) * 1000.0 > deadline_ms:
            v = "unknown"
        results[key] = v
    return {"results": {str(k): v for k, v in results.items()},
            "coverage": coverage(fitted, results),
            "total_runs": fitted["total_runs"],
            "decided_paths": sum(1 for v in results.values()
                                 if v in ("proved", "refuted"))}
