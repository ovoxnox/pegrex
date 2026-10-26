"""Executable compliance relationship graph; legal interpretation stays human-reviewed."""
from __future__ import annotations

import hashlib
import json

SCHEMA = "pegrex.executable-compliance-map.v1"


def _identity(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    default=str).encode()).hexdigest()


def build_compliance_map(classifications, flows, lifecycle, infrastructure, *, legal_review=None) -> dict:
    """Join declared data, trace, deletion/retention, and infrastructure evidence."""
    nodes, edges, unknowns = [], [], []
    try:
        classification_ids = set()
        for row in classifications:
            identifier = row["id"]
            if identifier in classification_ids:
                raise ValueError("duplicate data classification")
            classification_ids.add(identifier)
            nodes.append({"id": f"classification:{identifier}", "kind": "data-classification",
                          "classification": identifier, "labels": sorted(row.get("labels") or []),
                          "source_evidence": row.get("source_evidence")})
        flow_ids = set()
        for row in flows:
            identifier, classification = row["id"], row["classification"]
            if classification not in classification_ids:
                unknowns.append(f"flow {identifier}:unknown classification {classification}")
            flow_ids.add(identifier)
            nodes.append({"id": f"flow:{identifier}", "kind": "source-sink-trace",
                          "classification": classification, "source": row.get("source"),
                          "sink": row.get("sink"), "trace": row.get("trace") or [],
                          "evidence": row.get("evidence"), "evidence_strength": row.get("evidence_strength", "unknown")})
            edges.append({"source": f"classification:{classification}", "target": f"flow:{identifier}",
                          "kind": "classifies-flow", "evidence": row.get("evidence")})
        lifecycle_classes = set()
        for row in lifecycle:
            classification = row["classification"]
            lifecycle_classes.add(classification)
            if classification not in classification_ids:
                unknowns.append(f"lifecycle:unknown classification {classification}")
            for kind, field in (("retention-function", "retention_function"),
                                ("deletion-function", "deletion_function")):
                function = row.get(field)
                if not function:
                    unknowns.append(f"{classification}:missing {field.replace('_', ' ')}")
                node_id = f"lifecycle:{classification}:{kind}"
                nodes.append({"id": node_id, "kind": kind, "classification": classification,
                              "function": function, "evidence": row.get("evidence"),
                              "verdict": "unknown",
                              "unknowns": ["static function mapping does not prove operational deletion or retention compliance"]})
                edges.append({"source": f"classification:{classification}", "target": node_id,
                              "kind": "governed-by", "evidence": row.get("evidence")})
        control_classes = set()
        for row in infrastructure:
            for classification in row.get("classifications") or []:
                control_classes.add(classification)
                if classification not in classification_ids:
                    unknowns.append(f"infrastructure {row['id']}:unknown classification {classification}")
                node_id = f"infrastructure:{row['id']}:{classification}"
                nodes.append({"id": node_id, "kind": "infrastructure-control",
                              "classification": classification, "control": row.get("control"),
                              "resource": row.get("resource"), "evidence": row.get("evidence"),
                              "verdict": row.get("verdict", "unknown")})
                edges.append({"source": f"classification:{classification}", "target": node_id,
                              "kind": "protected-by", "evidence": row.get("evidence")})
        for classification in sorted(classification_ids):
            if not any(row.get("classification") == classification for row in flows):
                unknowns.append(f"{classification}:no source/sink trace supplied")
            if classification not in lifecycle_classes:
                unknowns.append(f"{classification}:retention/deletion mapping absent")
            if classification not in control_classes:
                unknowns.append(f"{classification}:infrastructure control mapping absent")
        if legal_review and legal_review.get("reviewer") and legal_review.get("decision"):
            legal = {"status": "human-reviewed", "reviewer": legal_review["reviewer"],
                     "decision": legal_review["decision"], "review_evidence": legal_review.get("evidence"),
                     "proved_by_code": False}
        else:
            legal = {"status": "human-review-required", "proved_by_code": False}
            unknowns.append("legal interpretation requires human review")
        nodes.sort(key=lambda row: row["id"])
        edges.sort(key=lambda row: (row["source"], row["target"], row["kind"]))
        payload = {"schema": SCHEMA, "schema_version": 1, "nodes": nodes, "edges": edges,
                   "legal_interpretation": legal}
        payload["map_identity"] = _identity(payload)
        payload["verdict"] = "unknown" if unknowns or any(
            row.get("verdict") == "unknown" for row in nodes) else "proved"
        payload["unknowns"] = sorted(set(unknowns))
        payload["scope"] = "declared technical relationships; no legal conclusion or operational-effectiveness proof"
        return payload
    except Exception as error:
        return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown",
                "nodes": [], "edges": [], "legal_interpretation": {"status": "human-review-required", "proved_by_code": False},
                "unknowns": [f"compliance map failed: {type(error).__name__}: {error}"]}


def query_compliance_map(graph, *, classification=None, kind=None, max_results=1000) -> dict:
    """Return matching nodes and directly supporting edges, bounded and fail-closed."""
    try:
        if graph.get("schema") != SCHEMA:
            raise ValueError("unsupported compliance map")
        nodes = [row for row in graph["nodes"]
                 if (classification is None or row.get("classification") == classification)
                 and (kind is None or row.get("kind") == kind)]
        if len(nodes) > max_results:
            return {"schema": "pegrex.compliance-map-query.v1", "verdict": "unknown",
                    "nodes": [], "edges": [], "unknowns": ["query result cap reached; no partial graph returned"]}
        ids = {row["id"] for row in nodes}
        edges = [row for row in graph["edges"] if row["source"] in ids or row["target"] in ids]
        incomplete = bool(graph.get("unknowns")) or any(row.get("verdict") == "unknown" for row in nodes)
        return {"schema": "pegrex.compliance-map-query.v1", "verdict": "unknown" if incomplete else "proved",
                "nodes": nodes, "edges": edges, "map_identity": graph.get("map_identity"),
                "legal_interpretation": graph.get("legal_interpretation"),
                "unknowns": list(graph.get("unknowns") or [])}
    except Exception as error:
        return {"schema": "pegrex.compliance-map-query.v1", "verdict": "unknown",
                "nodes": [], "edges": [], "unknowns": [str(error)]}
