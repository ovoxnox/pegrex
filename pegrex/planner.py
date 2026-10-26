"""Risk-aware refactoring plans ranked by evidence, impact, and proof effort."""
from __future__ import annotations

import hashlib
import json
import math

SCHEMA = "pegrex.risk-aware-change-plan.v1"


def plan_changes(graph, candidates: list[dict]) -> dict:
    """Implement plan changes with the module's explicit API and failure semantics."""
    rows, unknowns = [], []
    for candidate in candidates:
        target = candidate.get("target")
        if target not in graph.nodes:
            matches = [key for key, node in graph.nodes.items()
                       if node["kind"] == "function" and
                       (key.endswith("::" + str(target)) or node.get("function") == target)]
            target = matches[0] if len(matches) == 1 else target
        if target not in graph.nodes:
            rows.append({"id": candidate.get("id"), "target": target,
                         "status": "unknown", "priority": None,
                         "reason": "target-not-in-semantic-graph"})
            unknowns.append(f"target-not-in-semantic-graph:{candidate.get('target')}")
            continue
        impact = [key for key in graph.impact(target)
                  if graph.nodes[key]["kind"] == "function"]
        dependencies = [key for key in graph.dependencies(target)
                        if graph.nodes[key]["kind"] == "function"]
        node = graph.nodes[target]
        try:
            benefit = float(candidate["benefit"])
            if not math.isfinite(benefit) or benefit < 0:
                raise ValueError("benefit must be finite and nonnegative")
            uncertainty = float(candidate.get("uncertainty", 1.0 if node.get("status") != "ok" else 0.0))
            if not 0 <= uncertainty <= 1:
                raise ValueError("uncertainty must be in [0,1]")
            effort = float(candidate.get("proof_effort", 1 + len(dependencies) / 10))
            if not math.isfinite(effort) or effort <= 0:
                raise ValueError("proof effort must be positive")
        except (KeyError, TypeError, ValueError) as error:
            rows.append({"id": candidate.get("id"), "target": target,
                         "status": "unknown", "priority": None, "reason": str(error),
                         "reachable_impact": impact})
            unknowns.append(f"unrankable-candidate:{candidate.get('id')}:{error}")
            continue
        risk = len(impact) * uncertainty
        value = benefit * (1 + math.log2(1 + len(impact)))
        priority = value / (effort * (1 + risk))
        rows.append({"id": candidate.get("id"), "target": target,
                     "description": candidate.get("description", ""),
                     "status": "ranked", "priority": priority,
                     "benefit": benefit, "reachable_impact": impact,
                     "dependency_count": len(dependencies), "uncertainty": uncertainty,
                     "proof_effort": effort, "risk": risk,
                     "required_evidence": ["semantic-contract-recheck", "dependent-impact-review",
                                            "policy-decision"]})
    rows.sort(key=lambda row: (row["status"] != "ranked",
                               -(row["priority"] or 0), str(row["id"])))
    payload = {"candidates": rows, "graph_revision": graph.revision}
    identity = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()
    return {"schema": SCHEMA, "plan_identity": identity, **payload,
            "unknowns": unknowns, "policy": "higher expected benefit per proof effort; uncertainty and reachable impact penalize rank"}
