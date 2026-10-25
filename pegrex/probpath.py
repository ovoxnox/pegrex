"""
probpath - probabilistic path analysis.

Paths are explicit (constraints, outcome) records. Traces may be legacy guard
sets or mappings with {"constraints": ..., "outcome": ...}. A guard-only
trace is assigned only when exactly one path has those constraints; ambiguous
runs are reported instead of being counted once for every outcome.
"""
from .refine import _norm_constraint


def path_key(contracts_path_entry):
    cs, res = contracts_path_entry[:2]
    return (frozenset(_norm_constraint(str(c)) for c in cs), str(res))


def _trace_parts(trace):
    if isinstance(trace, dict):
        return trace.get("constraints", trace.get("guards", ())), trace.get("outcome")
    if (isinstance(trace, tuple) and len(trace) == 2
            and not isinstance(trace[1], (set, frozenset, list, tuple))):
        return trace[0], trace[1]
    return trace, None


def fit(contracts, traces):
    """Fit observed path counts without ever assigning one run twice."""
    paths = [(path_key(entry), entry[1]) for entry in contracts]
    total = matched = ambiguous = 0
    counts = {key: 0 for key, _ in paths}
    for trace in traces:
        total += 1
        guards, outcome = _trace_parts(trace)
        normalized = frozenset(_norm_constraint(str(g)) for g in guards)
        candidates = [key for key, _ in paths if key[0] == normalized
                      and (outcome is None or key[1] == str(outcome))]
        if len(candidates) == 1:
            counts[candidates[0]] += 1
            matched += 1
        elif len(candidates) > 1:
            ambiguous += 1
    rows = []
    for key, res in paths:
        constraints, keyed_outcome = key
        freq = counts[key] / total if total else 0.0
        rows.append({"constraints": sorted(constraints), "result": str(res),
                     "count": counts[key], "frequency": round(freq, 4)})
    return {"total_runs": total, "matched_runs": matched,
            "ambiguous_runs": ambiguous,
            "unmatched_runs": total - matched - ambiguous, "paths": rows}


def prioritize(fitted, sinks=(), top=None):
    """Rank by frequency, boosted when the path touches a sink."""
    def risk(row):
        text = " ".join(row["constraints"]) + " " + row["result"]
        return any(s in text for s in sinks)
    ranked = sorted(fitted["paths"],
                    key=lambda r: (-(r["frequency"] + (0.5 if risk(r) else 0.0)),
                                   sorted(r["constraints"]), r["result"]))
    return ranked[:top] if top else ranked
