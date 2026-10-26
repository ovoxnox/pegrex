"""Live semantic dependencies among functions, contracts, and invariants."""
from __future__ import annotations

import json
import hashlib
import os
from pathlib import Path

SCHEMA = "pegrex.semantic-dependency-graph.v1"


def _identity(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class SemanticDependencyGraph:
    def __init__(self, memory) -> None:
        self.memory = memory
        self.nodes = {}
        self.edges = []
        self.revision = None

    def refresh(self) -> dict:
        """Implement refresh with the module's explicit API and failure semantics."""
        if self.memory.memory_identity is None:
            self.memory.refresh()
        old_nodes = self.nodes
        self.nodes, self.edges = {}, []
        for path, architecture in sorted(self.memory.architecture.items()):
            module = f"module:{path}"
            self._node(module, "module", path=path,
                       source_sha256=architecture["source_sha256"])
        for key, api in sorted(self.memory.apis.items()):
            self._node(key, "function", path=api["path"], function=api["function"],
                       function_sha256=api["function_sha256"], status=api["status"])
            module = f"module:{api['path']}"
            self._edge(module, key, "contains")
            for contract in api["contracts"]:
                contract_key = f"contract:{_identity(contract)}"
                invariant_key = f"invariant:{_identity(contract)}"
                self._node(contract_key, "contract", function=key,
                           constraints=contract["constraints"], outcome=contract["outcome"])
                self._node(invariant_key, "invariant", function=key,
                           invariant_kind="path-contract", status=api["status"])
                self._edge(key, contract_key, "defines")
                self._edge(contract_key, invariant_key, "witnesses")
            for dependency in api["dependencies"]:
                candidates = [candidate for candidate, row in self.memory.apis.items()
                              if candidate != key and (row["function"] == dependency or
                                                       row["function"].endswith("." + dependency))]
                for callee in sorted(candidates):
                    self._edge(key, callee, "calls",
                               resolution="conservative" if len(candidates) > 1 else "resolved")
        for path, architecture in sorted(self.memory.architecture.items()):
            source = f"module:{path}"
            for imported in architecture["imports"]:
                for other in self.memory.architecture:
                    module_name = Path(other).with_suffix("").as_posix().replace("/", ".")
                    if imported == module_name or imported.endswith("." + Path(other).stem):
                        self._edge(source, f"module:{other}", "imports")
        self.revision = self.memory.memory_identity
        changed = sorted(key for key in set(self.nodes) | set(old_nodes)
                         if old_nodes.get(key) != self.nodes.get(key))
        impacted = sorted(set().union(*(self.impact(key) for key in changed))) if changed else []
        return {"schema": SCHEMA, "revision": self.revision, "changed": changed,
                "impacted": sorted(set(impacted + changed)), "nodes": len(self.nodes),
                "edges": len(self.edges), "unknowns": list(self.memory.limitations)}

    def _node(self, key, kind, **metadata):
        self.nodes[key] = {"id": key, "kind": kind, **metadata}

    def _edge(self, source, target, kind, **metadata):
        self.edges.append({"source": source, "target": target, "kind": kind, **metadata})

    def _walk(self, node, *, reverse=False, max_depth=100) -> set[str]:
        if node not in self.nodes:
            return set()
        adjacency = {}
        for edge in self.edges:
            source, target = (edge["target"], edge["source"]) if reverse else (edge["source"], edge["target"])
            adjacency.setdefault(source, set()).add(target)
        seen, frontier, depth = set(), {node}, 0
        while frontier and depth < max_depth:
            following = set().union(*(adjacency.get(row, set()) for row in frontier)) - seen - {node}
            seen.update(following)
            frontier = following
            depth += 1
        return seen

    def dependencies(self, node: str, *, max_depth=100) -> list[str]:
        """Implement dependencies with the module's explicit API and failure semantics."""
        return sorted(self._walk(node, max_depth=max_depth))

    def impact(self, node: str, *, max_depth=100) -> list[str]:
        """Implement impact with the module's explicit API and failure semantics."""
        return sorted(self._walk(node, reverse=True, max_depth=max_depth))

    def payload(self) -> dict:
        """Implement payload with the module's explicit API and failure semantics."""
        return {"schema": SCHEMA, "revision": self.revision,
                "nodes": [self.nodes[key] for key in sorted(self.nodes)],
                "edges": sorted(self.edges, key=lambda row: (row["source"], row["target"], row["kind"])),
                "unknowns": list(self.memory.limitations)}

    def save(self, path: str | Path) -> None:
        """Implement save with the module's explicit API and failure semantics."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(self.payload(), sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, path)
