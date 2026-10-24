"""
probpath - probabilistic path analysis.

Path frequencies estimated from production traces: a run is a frozenset of
taken guard atoms; a path is the constraint set of one enumerated contract.
Frequency = matching runs / total. prioritize() ranks paths by frequency,
boosted when the path touches a sink. Paths never seen are honestly 0 --
never estimated, never smoothed into existence.
"""
from .refine import _norm_constraint


def path_key(contracts_path_entry):
    cs, _res = contracts_path_entry
    return frozenset(_norm_constraint(str(c)) for c in cs)


def fit(contracts, traces):
    """contracts: api.contracts tuples. traces: iterable of guard-string
    sets (what each production run actually satisfied)."""
    paths = [(path_key(e), e[1]) for e in contracts]
    total = 0
    counts = {pk: 0 for pk, _ in paths}
    for t in traces:
        total += 1
        tn = frozenset(_norm_constraint(str(g)) for g in t)
        for pk, _ in paths:
            if pk == tn:
                counts[pk] += 1
    rows = []
    for pk, res in paths:
        freq = counts[pk] / total if total else 0.0
        rows.append({"constraints": sorted(pk), "result": str(res),
                     "count": counts[pk], "frequency": round(freq, 4)})
    return {"total_runs": total, "paths": rows}


def prioritize(fitted, sinks=(), top=None):
    """Rank by frequency, boosted when the path touches a sink."""
    def risk(row):
        """risk(row): see module docstring."""
        text = " ".join(row["constraints"]) + " " + row["result"]
        return any(s in text for s in sinks)
    ranked = sorted(fitted["paths"],
                    key=lambda r: (-(r["frequency"] + (0.5 if risk(r) else 0.0)),
                                   sorted(r["constraints"])))
    return ranked[:top] if top else ranked
