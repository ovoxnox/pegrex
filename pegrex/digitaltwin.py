"""Content-identified repository digital twin over independent graph evidence."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .repomemory import RepositoryMemory
from .semgraph import SemanticDependencyGraph
from .twin import build as build_call_twin

SCHEMA = "pegrex.repository-digital-twin.v1"


def build_repository_twin(root, *, boundaries=None, change_history=None,
                          risk_exposures=()) -> dict:
    """Join calls, owners, contracts, dependencies, history, and risk signals."""
    root = Path(root).resolve()
    try:
        calls = build_call_twin(str(root))
        memory = RepositoryMemory(root, boundaries=boundaries)
        memory.refresh()
        semantic = SemanticDependencyGraph(memory)
        semantic.refresh()
        unknowns = list(memory.limitations)
        history = list(change_history) if change_history is not None else []
        if change_history is None:
            unknowns.append("change history not supplied")
        unknown_contracts = sorted(key for key, row in memory.apis.items()
                                   if row["status"] != "ok" or row["unknowns"])
        unowned = sorted(name for name in calls["functions"] if not calls["owners"].get(name))
        exposure = {"declared": list(risk_exposures),
                    "unknown_contract_functions": unknown_contracts,
                    "unowned_functions": unowned}
        payload = {"schema": SCHEMA, "schema_version": 1,
                   "root_name": root.name,
                   "call_graph": {"functions": calls["functions"], "calls": calls["calls"],
                                  "files": {name: str(Path(path).relative_to(root))
                                            for name, path in calls["files"].items()}},
                   "ownership": calls["owners"],
                   "repository_memory": memory.payload(),
                   "contract_dependency_graph": semantic.payload(),
                   "change_history": history,
                   "risk_exposure": exposure}
        payload["twin_identity"] = hashlib.sha256(json.dumps(
            payload, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
        payload["unknowns"] = sorted(set(unknowns))
        payload["scope"] = "indexed static graphs and supplied history/risk evidence; unseen runtime paths remain possible"
        return payload
    except Exception as error:
        return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown",
                "unknowns": [f"digital-twin construction failed: {type(error).__name__}: {error}"]}


def twin_function_risk(twin, function) -> dict:
    """Return reverse contract impact and risk evidence for one function."""
    graph = twin.get("contract_dependency_graph") or {}
    edges = graph.get("edges") or []
    impact, frontier = set(), {function}
    for _ in range(100):
        following = {edge["source"] for edge in edges
                     if edge["target"] in frontier and edge["source"] not in impact}
        if not following:
            break
        impact.update(following)
        frontier = following
    else:
        return {"function": function, "verdict": "unknown",
                "unknowns": ["impact traversal bound reached"]}
    exposure = twin.get("risk_exposure") or {}
    return {"function": function,
            "impact": sorted(node for node in impact if not node.startswith("module:")),
            "dependency_impact": sorted(impact),
            "unknown_contract": function in exposure.get("unknown_contract_functions", []),
            "unowned": function in exposure.get("unowned_functions", []),
            "declared_exposures": [row for row in exposure.get("declared", [])
                                   if row.get("function") == function],
            "unknowns": list(twin.get("unknowns") or [])}
