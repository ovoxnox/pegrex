"""Continuous claim/evidence graph with exact upstream invalidation identities."""
from __future__ import annotations

import hashlib
import json

SCHEMA = "pegrex.continuous-assurance-graph.v1"
_MAX_CLAIMS = 10_000
_MAX_EVIDENCE_PER_CLAIM = 1_000
_MAX_EDGES = 50_000
_MAX_ID_LENGTH = 512
_MAX_STATEMENT_LENGTH = 20_000
_KINDS = {"api-contract", "access-policy", "taint-invariant", "migration-property"}


def _identity(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def build_assurance_graph(claims) -> dict:
    """Build nodes from claims and evidence edges pinned to upstream content."""
    nodes, edges, unknowns = [], [], []
    seen = set()
    try:
        if not isinstance(claims, (list, tuple)) or len(claims) > _MAX_CLAIMS:
            raise ValueError("claim list exceeds assurance graph budget")
        for claim in claims:
            if not isinstance(claim, dict):
                raise ValueError("claim must be an object")
            identifier = claim["id"]
            if (not isinstance(identifier, str) or not identifier
                    or len(identifier) > _MAX_ID_LENGTH or identifier in seen):
                raise ValueError("claim IDs must be bounded, nonempty strings and unique")
            seen.add(identifier)
            kind = claim["kind"]
            if kind not in _KINDS:
                raise ValueError(f"unsupported claim kind: {kind}")
            verdict = claim.get("verdict", "unknown")
            if verdict not in {"proved", "refuted", "unknown"}:
                verdict = "unknown"
                unknowns.append(f"{identifier}:invalid claim verdict normalized to UNKNOWN")
            statement = claim.get("statement")
            if statement is not None and (
                    not isinstance(statement, str) or len(statement) > _MAX_STATEMENT_LENGTH):
                raise ValueError(f"{identifier}: statement exceeds assurance graph budget")
            evidence_rows = claim.get("evidence") or []
            if not isinstance(evidence_rows, (list, tuple)) or len(evidence_rows) > _MAX_EVIDENCE_PER_CLAIM:
                raise ValueError(f"{identifier}: evidence list exceeds assurance graph budget")
            if len(edges) + sum(len(row.get("upstream") or []) for row in evidence_rows
                                if isinstance(row, dict)) > _MAX_EDGES:
                raise ValueError("assurance graph edge budget exceeded")
            if verdict == "proved" and not evidence_rows:
                verdict = "unknown"
                unknowns.append(f"{identifier}:proof claim has no evidence")
            node = {"id": identifier, "kind": kind, "verdict": verdict,
                    "statement": statement,
                    "evidence": [], "unknowns": list(claim.get("unknowns") or [])}
            if node["unknowns"] and verdict == "proved":
                node["verdict"] = "unknown"
            for evidence in evidence_rows:
                if not isinstance(evidence, dict):
                    raise ValueError(f"{identifier}: evidence row must be an object")
                evidence_id = evidence.get("id")
                if not isinstance(evidence_id, str) or not evidence_id or len(evidence_id) > _MAX_ID_LENGTH:
                    raise ValueError(f"{identifier}: evidence ID is invalid")
                upstream_rows = evidence.get("upstream") or []
                if not isinstance(upstream_rows, (list, tuple)):
                    raise ValueError(f"{identifier}: upstream must be a list")
                evidence_identity = _identity(evidence)
                node["evidence"].append({"id": evidence_id, "identity": evidence_identity,
                                         "verdict": evidence.get("verdict", "unknown")})
                upstreams = upstream_rows
                if evidence.get("verdict") == "proved" and not upstreams:
                    node["verdict"] = "unknown"
                    node["unknowns"].append(f"evidence {evidence_id} has no upstream identity")
                for upstream in upstreams:
                    if not isinstance(upstream, dict):
                        node["verdict"] = "unknown"
                        node["unknowns"].append(f"evidence {evidence_id} has malformed upstream identity")
                        continue
                    if not isinstance(upstream.get("id"), str) or not upstream.get("id") or not isinstance(upstream.get("sha256"), str) or not upstream.get("sha256"):
                        node["verdict"] = "unknown"
                        node["unknowns"].append(f"evidence {evidence_id} has incomplete upstream identity")
                    edges.append({"source": identifier, "target": upstream.get("id"),
                        "kind": "depends-on", "evidence_id": evidence_id,
                        "evidence_identity": evidence_identity,
                        "upstream_sha256": upstream.get("sha256"),
                        "upstream_path": upstream.get("path")})
            node["unknowns"] = sorted(set(node["unknowns"]))
            nodes.append(node)
        nodes.sort(key=lambda row: row["id"])
        edges.sort(key=lambda row: (row["source"], row["evidence_id"], str(row["target"])))
        payload = {"schema": SCHEMA, "schema_version": 1, "nodes": nodes, "edges": edges}
        payload["graph_identity"] = _identity(payload)
        payload["unknowns"] = sorted(set(unknowns + [f"{row['id']}:{reason}" for row in nodes
                                                     for reason in row["unknowns"]]))
        payload["verdict"] = "unknown" if payload["unknowns"] or any(
            row["verdict"] == "unknown" for row in nodes) else (
            "refuted" if any(row["verdict"] == "refuted" for row in nodes) else "proved")
        return payload
    except Exception as error:
        return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown",
                "nodes": [], "edges": [], "unknowns": [f"assurance graph failed: {error}"]}


def invalidate_assurance(graph, upstream_changes) -> dict:
    """Invalidate only exact changed upstreams; stale proof becomes UNKNOWN."""
    try:
        if graph.get("schema") != SCHEMA or _identity({key: graph[key] for key in (
                "schema", "schema_version", "nodes", "edges")}) != graph.get("graph_identity"):
            raise ValueError("assurance graph identity mismatch")
        changes = dict(upstream_changes)
        nodes = {row["id"]: dict(row, evidence=list(row["evidence"]), unknowns=list(row["unknowns"]))
                 for row in graph["nodes"]}
        invalidated_edges = []
        for edge in graph["edges"]:
            upstream = edge["target"]
            if upstream not in changes:
                continue
            current = changes[upstream]
            exact = isinstance(current, dict) and current.get("sha256") == edge["upstream_sha256"]
            if exact:
                continue
            invalidated_edges.append(dict(edge, current_upstream=current,
                invalidation="exact upstream content changed" if isinstance(current, dict) else
                             "upstream marked changed; current content identity unavailable"))
            node = nodes[edge["source"]]
            if node["verdict"] == "proved":
                node["verdict"] = "unknown"
            node["unknowns"].append(f"evidence {edge['evidence_id']} invalidated by upstream {upstream}")
        for node in nodes.values():
            node["unknowns"] = sorted(set(node["unknowns"]))
        ordered_nodes = [nodes[key] for key in sorted(nodes)]
        payload = {"schema": SCHEMA, "schema_version": 1,
                   "nodes": ordered_nodes, "edges": graph["edges"]}
        payload["graph_identity"] = _identity(payload)
        payload["base_graph_identity"] = graph["graph_identity"]
        payload["invalidated_edges"] = invalidated_edges
        payload["unknowns"] = sorted(set(f"{row['id']}:{reason}" for row in ordered_nodes
                                          for reason in row["unknowns"]))
        payload["verdict"] = "unknown" if payload["unknowns"] or invalidated_edges else graph["verdict"]
        payload["scope"] = "exact content invalidation; unchanged edges retain their original evidence status"
        return payload
    except Exception as error:
        return {"schema": SCHEMA, "verdict": "unknown", "nodes": [], "edges": [],
                "unknowns": [f"assurance invalidation failed: {error}"]}


def query_assurance(graph, *, kind=None, verdict=None) -> dict:
    """Query claims without converting absent matches into assurance."""
    try:
        rows = [row for row in graph["nodes"]
                if (kind is None or row["kind"] == kind) and
                   (verdict is None or row["verdict"] == verdict)]
        return {"schema": "pegrex.assurance-query.v1", "claims": rows,
                "count": len(rows), "graph_identity": graph.get("graph_identity"),
                "verdict": "unknown" if not rows else "proved",
                "unknowns": [] if rows else ["no claims matched; absence is not a clean assurance result"]}
    except Exception as error:
        return {"schema": "pegrex.assurance-query.v1", "verdict": "unknown",
                "claims": [], "unknowns": [str(error)]}
