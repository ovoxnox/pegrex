"""Evidence-first context compression and local repository memory graph."""
from __future__ import annotations
import hashlib, json
from pathlib import Path

MEMORY_SCHEMA = "pegrex.memory-graph.v1"

def compress_context(*, contracts=(), invariants=(), dependencies=(), evidence=(), obligations=(), max_items=500) -> dict:
    """Retain structured evidence; never paraphrase away unresolved obligations."""
    fields = {"contracts": list(contracts), "invariants": list(invariants), "dependencies": list(dependencies),
              "evidence": list(evidence), "unresolved_obligations": list(obligations)}
    kept = {}
    for name, rows in fields.items():
        kept[name] = rows[:max_items]
    canonical = json.dumps(kept, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return {"schema": "pegrex.agent-context.v1", "items": kept,
            "truncated": {name: max(0, len(fields[name]) - len(kept[name])) for name in fields},
            "sha256": hashlib.sha256(canonical.encode()).hexdigest(),
            "principle": "evidence-preserving; unresolved obligations are never silently dropped"}

class MemoryGraph:
    """Reviewable local JSON memory; each node is content-addressed and typed."""
    def __init__(self, path: str | Path): self.path = Path(path); self.nodes = {}; self.edges = []
    def add(self, kind: str, payload: dict, *, relates_to=()) -> str:
        if kind not in {"bug", "repair", "failed_patch", "constraint", "regression_test", "finding"}:
            raise ValueError("unsupported memory node kind")
        canonical = json.dumps({"kind": kind, "payload": payload}, sort_keys=True, separators=(",", ":"), default=str)
        node_id = hashlib.sha256(canonical.encode()).hexdigest()
        targets = list(relates_to)
        missing = [target for target in targets if target not in self.nodes]
        if missing: raise KeyError(f"unknown related memory node: {missing[0]}")
        self.nodes[node_id] = {"id": node_id, "kind": kind, "payload": payload}
        for target in targets:
            self.edges.append({"from": node_id, "to": target})
        return node_id
    def save(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        doc = {"schema": MEMORY_SCHEMA, "nodes": [self.nodes[k] for k in sorted(self.nodes)], "edges": sorted(self.edges, key=lambda e: (e["from"], e["to"]))}
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8"); tmp.replace(self.path)
        return self.path
    def load(self):
        doc = json.loads(self.path.read_text(encoding="utf-8"))
        if doc.get("schema") != MEMORY_SCHEMA: raise ValueError("unsupported memory graph schema")
        self.nodes = {node["id"]: node for node in doc.get("nodes", [])}; self.edges = doc.get("edges", [])
        if any(edge.get("from") not in self.nodes or edge.get("to") not in self.nodes for edge in self.edges): raise ValueError("memory graph contains dangling edge")
        return self
