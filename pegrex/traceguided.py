"""Production-trace-guided symbolic path prioritization with unseen-path retention."""
from __future__ import annotations

import math

from .smt import auto_feasible

SCHEMA = "pegrex.trace-guided-paths.v1"


def prioritize_symbolic_paths(paths, traces=(), *, max_paths=1000) -> dict:
    """Rank feasible untested/high-risk paths without deleting unseen paths."""
    rows, unknowns = [], []
    observed_ids = {trace.get("path_id") for trace in traces if trace.get("path_id")}
    if len(paths) > max_paths:
        return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown",
                "paths": [], "unknowns": ["path budget reached; prioritized set incomplete"]}
    for path in paths:
        identifier = path.get("id")
        constraints = list(path.get("constraints") or [])
        try:
            risk = float(path.get("risk", 1.0))
            if not identifier or not math.isfinite(risk) or risk < 0:
                raise ValueError("path requires an id and finite nonnegative risk")
            feasible = auto_feasible(constraints)
            exact_test = identifier in observed_ids
            possible_traces = []
            if not exact_test:
                for index, trace in enumerate(traces):
                    if trace.get("path_id") or not trace.get("constraints"):
                        continue
                    combined = auto_feasible(constraints + list(trace["constraints"]))
                    if combined is True:
                        possible_traces.append(index)
                    elif combined is None:
                        unknowns.append(f"{identifier}: trace compatibility unknown")
            if feasible is False:
                coverage, priority = "proved-infeasible", 0.0
            else:
                coverage = ("observed" if exact_test else
                            "possibly-observed" if possible_traces else "unseen")
                priority = risk * (1.0 if exact_test else 2.0)
                if feasible is None:
                    priority += 1.0
                    unknowns.append(f"{identifier}: symbolic feasibility unknown")
                if possible_traces:
                    unknowns.append(f"{identifier}: compatible trace constraints do not confirm exact path coverage")
            rows.append({"id": identifier, "constraints": constraints,
                         "outcome": path.get("outcome"), "risk": risk,
                         "feasibility": feasible, "coverage": coverage,
                         "possible_trace_indices": possible_traces,
                         "priority": priority,
                         "unknowns": [] if feasible is not None else ["feasibility unknown"]})
        except Exception as error:
            unknowns.append(f"{identifier or '<missing-id>'}: {error}")
            rows.append({"id": identifier, "coverage": "unknown", "priority": 0.0,
                         "feasibility": None, "unknowns": [str(error)]})
    rows.sort(key=lambda row: (-row["priority"], str(row.get("id"))))
    if any(row["coverage"] == "unseen" for row in rows):
        unknowns.append("unseen paths are unobserved, not impossible")
    return {"schema": SCHEMA, "schema_version": 1,
            "verdict": "unknown" if unknowns else "proved",
            "paths": rows, "unknowns": sorted(set(unknowns)),
            "coverage": {"total": len(rows),
                         "observed": sum(row["coverage"] == "observed" for row in rows),
                         "unseen": sum(row["coverage"] == "unseen" for row in rows)},
            "scope": "bounded symbolic feasibility and declared trace evidence"}
