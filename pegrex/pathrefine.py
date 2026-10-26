"""Path feasibility and subsumption with retained removal evidence."""
from __future__ import annotations
from .core.models import contracts_from_pairs
from .core.contracts import subsume
from .smt import auto_feasible

SCHEMA = "pegrex.path-refinement.v1"


def refine_paths(paths, *, semantic=True) -> dict:
    """Remove only proved-infeasible or dominated paths; retain unknown paths."""
    rows = contracts_from_pairs(paths)
    kept, removed, unknowns = [], [], []
    for row in rows:
        verdict = auto_feasible(row.constraints)
        if verdict is False:
            removed.append({"path": row.to_dict(), "reason": "infeasible",
                            "evidence": {"method": "QF_LIA feasibility", "verdict": "unsat"}})
        else:
            if verdict is None:
                unknowns.append(f"feasibility unknown: {row.identity}")
            kept.append(row)
    report = subsume(kept, semantic=semantic)
    removed.extend({"path": row["path"], "reason": "constraint-dominated",
                    "evidence": {"subsumed_by": row["subsumed_by"], "method": row["reason"]}}
                   for row in report["removed"])
    unknowns.extend(report.get("unknowns", []))
    return {"schema": SCHEMA, "schema_version": 1,
            "verdict": "unknown" if unknowns else "ok",
            "input_count": len(rows), "kept": report["kept"], "removed": removed,
            "unknowns": sorted(set(unknowns)),
            "soundness": "only infeasible or same-behavior dominated paths removed"}
