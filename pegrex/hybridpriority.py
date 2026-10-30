"""Hybrid symbolic/neural scheduling seam; heuristics never determine verdicts."""
from __future__ import annotations
SCHEMA = "pegrex.hybrid-priority.v1"

def prioritize_paths(paths, *, heuristic=None, max_paths=None):
    """Order paths by heuristic score, preserving original index as deterministic tie-break.

    `heuristic(path)` may be learned, but only influences exploration order. It
    cannot upgrade or downgrade proof verdicts. Every omitted path is reported.
    """
    rows, errors = [], []
    for i, path in enumerate(paths):
        try:
            score = float(heuristic(path)) if heuristic else 0.0
            if score != score or score in (float("inf"), float("-inf")): score = 0.0
        except Exception as exc:
            score = 0.0
            errors.append({"index": i, "reason": type(exc).__name__})
        rows.append({"index": i, "path": path, "priority": score})
    rows.sort(key=lambda r: (-r["priority"], r["index"]))
    limit = len(rows) if max_paths is None else max(0, int(max_paths))
    selected, deferred = rows[:limit], rows[limit:]
    return {"schema": SCHEMA, "selected": selected, "deferred": [r["index"] for r in deferred],
            "heuristic_errors": errors, "verdict_authority": "sound-checker-or-independent-evidence-only",
            "heuristic_can_set_verdict": False}
