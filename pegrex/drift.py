"""Architecture drift over intended import and internal call boundaries."""
from __future__ import annotations

from pathlib import Path

from .repomemory import RepositoryMemory
from .semgraph import SemanticDependencyGraph

SCHEMA = "pegrex.architecture-drift.v1"


def _module_name(path):
    return Path(path).with_suffix("").as_posix().replace("/", ".")


def detect_architecture_drift(root, boundaries) -> dict:
    """Compare declarative allowed dependencies with imports and call edges."""
    try:
        memory = RepositoryMemory(root, boundaries=boundaries)
        memory.refresh()
        graph = SemanticDependencyGraph(memory)
        graph.refresh()
        drift = []
        for path, architecture in sorted(memory.architecture.items()):
            for imported in architecture["violations"]:
                drift.append({"kind": "unintended-import", "source": path,
                              "target": imported, "allowed": architecture["allowed_imports"]})
        for edge in graph.edges:
            if edge["kind"] != "calls":
                continue
            source_api = memory.apis.get(edge["source"])
            target_api = memory.apis.get(edge["target"])
            if not source_api or not target_api or source_api["path"] == target_api["path"]:
                continue
            allowed = memory.boundaries.get(source_api["path"], memory.boundaries.get("*"))
            if allowed is None:
                continue
            target_module = _module_name(target_api["path"])
            if not any(target_module == prefix or target_module.startswith(prefix + ".")
                       for prefix in allowed):
                drift.append({"kind": "unintended-call-coupling",
                              "source": edge["source"], "target": edge["target"],
                              "source_path": source_api["path"],
                              "target_path": target_api["path"], "allowed": allowed,
                              "resolution": edge.get("resolution")})
        unknowns = list(memory.limitations)
        verdict = "refuted" if drift else "unknown" if unknowns else "proved"
        return {"schema": SCHEMA, "schema_version": 1, "verdict": verdict,
                "drift": drift, "unknowns": unknowns,
                "evidence": {"memory_identity": memory.memory_identity,
                             "graph_revision": graph.revision,
                             "imports_checked": len(memory.architecture),
                             "call_edges_checked": sum(row["kind"] == "calls" for row in graph.edges)},
                "scope": "registered repository imports and conservatively resolved internal calls"}
    except Exception as error:
        return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown",
                "drift": [], "unknowns": [f"architecture drift analysis failed: {type(error).__name__}: {error}"]}
