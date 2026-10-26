"""Pre-merge simulation of contract, policy, client, flow, and downstream impact."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path, PurePosixPath

from .changebudget import summarize_semantic_change
from .drift import detect_architecture_drift
from .repomemory import RepositoryMemory
from .roundtrip import generate_api_stubs
from .semgraph import SemanticDependencyGraph

SCHEMA = "pegrex.change-impact-simulation.v1"


def _safe_relative(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not name:
        raise ValueError("proposed change paths must be safe repository-relative paths")
    return path.as_posix()


def simulate_change_impact(root, proposed_changes, *, boundaries=None, api_specs=None) -> dict:
    """Evaluate a staged repository copy; never modify the real merge target."""
    root = Path(root).resolve()
    unknowns = []
    try:
        if not proposed_changes:
            raise ValueError("at least one proposed source change is required")
        changes = {_safe_relative(name): source for name, source in proposed_changes.items()}
        with tempfile.TemporaryDirectory(prefix="pegrex-impact-") as directory:
            staged = Path(directory) / "after"
            shutil.copytree(root, staged)
            for name, source in changes.items():
                target = staged / name
                if target.is_symlink() or any(part.is_symlink() for part in target.parents if part != staged.parent):
                    raise ValueError("symbolic-link change path refused")
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(source, encoding="utf-8")
            summary = summarize_semantic_change(root, staged)
            unknowns.extend(summary["unknown_regions"])
            memory = RepositoryMemory(staged); memory.refresh()
            graph = SemanticDependencyGraph(memory); graph.refresh()
            changed_nodes = {row["api"] for row in summary["public_contract_changes"]}
            impacted_nodes = set()
            for node in sorted(changed_nodes):
                impacted_nodes.update(graph.impact(node))
            impacted_apis = sorted(node for node in impacted_nodes if node in memory.apis)
            downstream_modules = sorted({memory.apis[node]["path"] for node in impacted_apis} |
                                        {node[len("module:"):] for node in impacted_nodes if node.startswith("module:")})
            contracts = [{"api": row["api"], "change": row["change"], "verdict": row["verdict"],
                          "may_invalidate": True} for row in summary["public_contract_changes"]]
            policy = detect_architecture_drift(staged, boundaries or {})
            unknowns.extend("policy:" + row for row in policy["unknowns"])
            clients = []
            for name, pair in sorted((api_specs or {}).items()):
                try:
                    before = generate_api_stubs(pair["before"])
                    after = generate_api_stubs(pair["after"])
                    changed = before != after
                    clients.append({"api": name, "may_invalidate": changed,
                        "operations_before": before["operations"], "operations_after": after["operations"],
                        "python_server_changed": before["python_server"] != after["python_server"],
                        "go_client_changed": before["go_client"] != after["go_client"],
                        "verdict": "unknown" if changed else "proved",
                        "unknowns": ["generated stub drift does not decide runtime compatibility"] if changed else []})
                    if changed:
                        unknowns.append(f"generated-client:{name}:runtime round-trip evidence required")
                except Exception as error:
                    clients.append({"api": name, "may_invalidate": True, "verdict": "unknown",
                                    "unknowns": [str(error)]})
                    unknowns.append(f"generated-client:{name}:{error}")
            flows = [{"change": row["change"], "finding": row["finding"], "may_invalidate": True}
                     for row in summary["security_surface_changes"]]
            verdict = "refuted" if summary["budget_exceeded"] else "unknown" if unknowns else "proved"
            return {"schema": SCHEMA, "schema_version": 1, "verdict": verdict,
                    "applied": False, "staged": True,
                    "contracts": contracts, "policies": policy,
                    "generated_clients": clients, "data_flows": flows,
                    "downstream_modules": downstream_modules,
                    "downstream_functions": impacted_apis,
                    "change_budget": summary, "unknowns": sorted(set(unknowns)),
                    "scope": "possible invalidation under staged static evidence; not merge authorization"}
    except Exception as error:
        return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown",
                "applied": False, "contracts": [], "generated_clients": [], "data_flows": [],
                "downstream_modules": [], "unknowns": [f"impact simulation failed: {type(error).__name__}: {error}"]}
