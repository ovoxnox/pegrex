"""Persistent repository memory derived from contracts, not chat prose."""
from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path

from .repository import RepositoryIndex

SCHEMA = "pegrex.repository-memory.v1"


def _identity(value) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode()).hexdigest()


class RepositoryMemory:
    def __init__(self, root: str | Path, *, boundaries=None, configuration=None) -> None:
        self.root = Path(root).resolve()
        self.boundaries = boundaries or {}
        self.configuration = configuration or {}
        self.index = RepositoryIndex(self.root, configuration=self.configuration)
        self.apis = {}
        self.invariants = {}
        self.architecture = {}
        self.limitations = []
        self.memory_identity = None

    def refresh(self) -> dict:
        """Implement refresh with the module's explicit API and failure semantics."""
        report = self.index.scan()
        snapshot = self.index.extractor.snapshot()
        summaries = {f"{row['path']}::{row['function']}": row["summary"]
                     for row in snapshot["summaries"]}
        self.apis = {}
        self.invariants = {}
        self.limitations = list(report["unknowns"])
        for key, summary in sorted(summaries.items()):
            api = {"path": summary["path"], "function": summary["function"],
                   "status": summary["status"], "function_sha256": summary["function_sha256"],
                   "source_sha256": summary["source_sha256"],
                   "dependencies": summary["dependencies"],
                   "contracts": summary["contracts"], "unknowns": summary["unknowns"]}
            api["api_identity"] = _identity(api)
            self.apis[key] = api
            self.invariants[key] = [{"kind": "path-contract",
                                     "contract_identity": _identity(contract),
                                     "status": summary["status"]}
                                    for contract in summary["contracts"]]
            self.limitations.extend(f"{key}: {reason}" for reason in summary["unknowns"])
        self.architecture = {}
        for document_path, document in sorted(snapshot["documents"].items()):
            path = self.root / document_path
            imports = []
            if document["language"] == "python" and path.is_file():
                try:
                    tree = ast.parse(path.read_text(encoding="utf-8"))
                    for node in ast.walk(tree):
                        if isinstance(node, ast.Import):
                            imports.extend(alias.name for alias in node.names)
                        elif isinstance(node, ast.ImportFrom) and node.module:
                            imports.append(node.module)
                except (OSError, SyntaxError, UnicodeError) as error:
                    self.limitations.append(f"{document_path}: architecture-unknown:{error}")
            allowed = self.boundaries.get(document_path, self.boundaries.get("*"))
            violations = [] if allowed is None else [name for name in imports
                if not any(name == prefix or name.startswith(prefix + ".") for prefix in allowed)]
            self.architecture[document_path] = {
                "source_sha256": document["source_sha256"], "imports": sorted(set(imports)),
                "allowed_imports": allowed, "violations": sorted(violations)}
        payload = self.payload(include_identity=False)
        self.memory_identity = _identity(payload)
        return self.payload()

    def payload(self, *, include_identity=True) -> dict:
        """Implement payload with the module's explicit API and failure semantics."""
        row = {"schema": SCHEMA, "root_name": self.root.name,
               "configuration": self.configuration, "boundaries": self.boundaries,
               "apis": self.apis, "invariants": self.invariants,
               "architecture": self.architecture,
               "limitations": sorted(set(self.limitations))}
        if include_identity:
            row["memory_identity"] = self.memory_identity
        return row

    def query_api(self, function: str) -> list[dict]:
        """Implement query api with the module's explicit API and failure semantics."""
        return [row for key, row in sorted(self.apis.items())
                if key == function or row["function"] == function or
                key.endswith("::" + function)]

    def save(self, path: str | Path) -> dict:
        """Implement save with the module's explicit API and failure semantics."""
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(json.dumps(self.payload(), sort_keys=True, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, destination)
        return {"schema": SCHEMA, "path": str(destination),
                "memory_identity": self.memory_identity}

    @classmethod
    def load(cls, root: str | Path, path: str | Path) -> "RepositoryMemory":
        """Implement load with the module's explicit API and failure semantics."""
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        if data.get("schema") != SCHEMA:
            raise ValueError("unsupported repository memory schema")
        memory = cls(root, boundaries=data.get("boundaries"),
                     configuration=data.get("configuration"))
        memory.apis = data["apis"]
        memory.invariants = data["invariants"]
        memory.architecture = data["architecture"]
        memory.limitations = data["limitations"]
        memory.memory_identity = data["memory_identity"]
        if memory.memory_identity != _identity(memory.payload(include_identity=False)):
            raise ValueError("repository memory identity mismatch")
        # Loaded memory is evidence until refresh; the index is rebuilt from the
        # persisted summaries so callers can explicitly scan for drift.
        memory.index.extractor.restore({"schema": "pegrex.incremental-contracts-state.v1",
            "analyzer_version": "incremental-contracts-v1", "documents": {},
            "summaries": [{"path": row["path"], "function": row["function"],
                           "summary": {key: value for key, value in row.items()
                                       if key in {"schema", "path", "function", "source_sha256",
                                                  "function_sha256", "dependencies", "status",
                                                  "contracts", "unknowns", "analyzer_version"}}}
                          for row in memory.apis.values()]})
        return memory
