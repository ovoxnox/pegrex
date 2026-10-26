"""Function-granular incremental path-contract extraction.

A function is reanalyzed only when its own body, relevant module context,
analyzer configuration, or a transitive callee revision changes. Incomplete
extraction is retained as UNKNOWN and never replaces a previous proof with a
truncated contract set.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path
from typing import Iterable

from .constraints import constraint_hash
from .schema import contract_document
from .sessions import AnalysisSession

SCHEMA = "pegrex.incremental-contracts.v1"
FUNCTION_SCHEMA = "pegrex.function-contracts.v1"
ANALYZER_VERSION = "incremental-contracts-v1"


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class _Calls(ast.NodeVisitor):
    def __init__(self) -> None:
        self.names: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Implement visit FunctionDef with the module's explicit API and failure semantics."""
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Implement visit AsyncFunctionDef with the module's explicit API and failure semantics."""
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Implement visit ClassDef with the module's explicit API and failure semantics."""
        return

    def visit_Call(self, node: ast.Call) -> None:
        """Implement visit Call with the module's explicit API and failure semantics."""
        if isinstance(node.func, ast.Name):
            self.names.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            self.names.add(node.func.attr)
        self.generic_visit(node)


def _context_digest(tree: ast.Module, source: str) -> str:
    """Digest non-function context that can affect contracts."""
    chunks: list[str] = []

    def top(body: Iterable[ast.stmt]) -> None:
        """Implement top with the module's explicit API and failure semantics."""
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if isinstance(node, ast.ClassDef):
                chunks.extend(ast.get_source_segment(source, base) or ast.unparse(base)
                              for base in node.bases)
                top(node.body)
            else:
                chunks.append(ast.get_source_segment(source, node) or ast.unparse(node))
    top(tree.body)
    return _digest("\n".join(chunks))


def _python_inventory(source: str) -> dict[str, dict]:
    tree = ast.parse(source)
    context = _context_digest(tree, source)
    functions: dict[str, dict] = {}

    def visit(body: list[ast.stmt], prefix: str = "") -> None:
        """Implement visit with the module's explicit API and failure semantics."""
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit(node.body, f"{prefix}{node.name}.")
                continue
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            name = f"{prefix}{node.name}"
            segment = ast.get_source_segment(source, node) or ast.unparse(node)
            calls = _Calls()
            for statement in node.body:
                calls.visit(statement)
            functions[name] = {
                "function_hash": _digest(segment),
                "revision_seed": _digest(context + "\0" + segment),
                "dependencies": tuple(sorted(calls.names)),
                "entrypoint": node.name,
                "line": node.lineno,
                "end_line": getattr(node, "end_lineno", node.lineno),
            }
            visit(node.body, name + ".")
    visit(tree.body)
    return functions


def _inventory(source: str, language: str) -> dict[str, dict]:
    if language == "python":
        return _python_inventory(source)
    # Non-Python frontends currently expose module-level extraction. This is
    # explicit granularity, not a claim that changed functions were identified.
    return {"<module>": {"function_hash": _digest(source),
                         "revision_seed": _digest(source),
                         "dependencies": (), "entrypoint": None,
                         "line": 1, "end_line": len(source.splitlines())}}


class IncrementalContractExtractor:
    def __init__(self, *, max_paths: int = 10_000, timeout_ms: int | None = None,
                 tree_cache: dict | None = None) -> None:
        self.max_paths = max_paths
        self.timeout_ms = timeout_ms
        self.tree_cache = tree_cache if tree_cache is not None else {}
        self._documents: dict[str, dict] = {}
        self._sessions: dict[str, AnalysisSession] = {}
        self._summaries: dict[tuple[str, str], dict] = {}

    @staticmethod
    def _key(path: str, function: str) -> str:
        return f"{path}::{function}"

    def _resolve(self, path: str, function: str, dependency: str) -> set[tuple[str, str]]:
        candidates = {(path, dependency)}
        if "." not in dependency:
            candidates.update(key for key in self._all_functions()
                              if key[0] == path and key[1].rsplit(".", 1)[-1] == dependency)
        # Cross-module calls are conservative: a matching exported function is
        # enough to invalidate. Extra invalidation is safe; missed callers not.
        candidates.update(key for key in self._all_functions()
                          if key[1] == dependency or key[1].endswith("." + dependency))
        candidates.discard((path, function))
        return candidates

    def _all_functions(self) -> set[tuple[str, str]]:
        return {(path, name) for path, document in self._documents.items()
                for name in document["functions"]}

    def _analyze(self, path: str, function: str) -> dict:
        document = self._documents[path]
        metadata = document["functions"][function]
        entrypoint = metadata["entrypoint"]
        base = {
            "schema": FUNCTION_SCHEMA,
            "path": path,
            "function": function,
            "source_sha256": document["source_sha256"],
            "function_sha256": metadata["function_hash"],
            "dependencies": list(metadata["dependencies"]),
            "analyzer_version": ANALYZER_VERSION,
        }
        try:
            pairs = self._sessions[path].contracts(entrypoint=entrypoint)
            contracts = [contract_document(
                constraints=sorted(map(str, guards)),
                constraint_identity=constraint_hash(guards), outcome=outcome)
                for guards, outcome in pairs]
            if not contracts:
                return {**base, "status": "unknown", "contracts": [],
                        "unknowns": ["no paths extracted; absence of behavior is not proved"]}
            return {**base, "status": "ok", "contracts": contracts, "unknowns": []}
        except Exception as exc:
            return {**base, "status": "unknown", "contracts": [],
                    "unknowns": [f"{type(exc).__name__}: {exc}"]}

    def update(self, path: str, source: str, language: str = "python") -> dict:
        """Implement update with the module's explicit API and failure semantics."""
        from .languages import normalize_language
        resolved = normalize_language(language)
        if resolved is None:
            raise ValueError(f"unsupported source language {language!r}")
        path = str(Path(path))
        previous = self._documents.get(path)
        functions = _inventory(source, resolved)
        document = {"language": resolved, "source_sha256": _digest(source),
                    "functions": functions}
        self._documents[path] = document
        if (previous is None or previous["source_sha256"] != document["source_sha256"]
                or path not in self._sessions):
            self._sessions[path] = AnalysisSession(
                source, resolved, path=path, timeout_ms=self.timeout_ms,
                max_paths=self.max_paths, tree_cache=self.tree_cache)

        old_functions = previous["functions"] if previous else {}
        direct = {name for name in functions
                  if name not in old_functions or
                  functions[name]["revision_seed"] != old_functions[name]["revision_seed"]}
        removed = set(old_functions) - set(functions)
        invalidated = {(path, name) for name in direct}
        removed_keys = {(path, name) for name in removed}

        # Reverse dependency closure across the current repository snapshot.
        frontier = list(invalidated | removed_keys)
        while frontier:
            changed = frontier.pop()
            for candidate_path, candidate_doc in self._documents.items():
                for name, metadata in candidate_doc["functions"].items():
                    candidate = (candidate_path, name)
                    if candidate in invalidated:
                        continue
                    for dependency in metadata["dependencies"]:
                        resolved = self._resolve(candidate_path, name, dependency)
                        removed_match = (changed[1] == dependency or
                                         changed[1].endswith("." + dependency))
                        if changed in resolved or (changed in removed_keys and removed_match):
                            invalidated.add(candidate)
                            frontier.append(candidate)
                            break

        for stale in removed_keys | invalidated:
            self._summaries.pop(stale, None)
        analyzed = sorted(invalidated)
        for key in analyzed:
            self._summaries[key] = self._analyze(*key)
        # Missing entries (for example after deserialization) are computed even
        # when their source text did not change.
        for key in sorted(self._all_functions() - set(self._summaries)):
            if key not in analyzed:
                analyzed.append(key)
                self._summaries[key] = self._analyze(*key)
        reused = sorted(set(self._summaries) - set(analyzed))
        return {
            "schema": SCHEMA,
            "path": path,
            "language": resolved,
            "source_sha256": document["source_sha256"],
            "granularity": "function" if resolved == "python" else "module",
            "changed": sorted(self._key(path, name) for name in direct),
            "removed": sorted(self._key(*key) for key in removed_keys),
            "invalidated": sorted(self._key(*key) for key in invalidated),
            "analyzed": sorted(self._key(*key) for key in analyzed),
            "reused": sorted(self._key(*key) for key in reused),
            "summaries": {self._key(*key): self._summaries[key]
                          for key in sorted(self._summaries)},
            "unknowns": [unknown for key in sorted(self._summaries)
                         for unknown in self._summaries[key]["unknowns"]],
        }

    def remove(self, path: str) -> dict:
        """Remove a document and conservatively invalidate its reverse callers."""
        path = str(Path(path))
        previous = self._documents.pop(path, None)
        self._sessions.pop(path, None)
        if previous is None:
            return {"schema": SCHEMA, "path": path, "removed": [],
                    "invalidated": [], "analyzed": [], "reused": []}
        removed_keys = {(path, name) for name in previous["functions"]}
        invalidated: set[tuple[str, str]] = set()
        frontier = list(removed_keys)
        while frontier:
            changed = frontier.pop()
            for candidate_path, document in self._documents.items():
                for name, metadata in document["functions"].items():
                    candidate = (candidate_path, name)
                    if candidate in invalidated:
                        continue
                    for dependency in metadata["dependencies"]:
                        removed_match = (changed[1] == dependency or
                                         changed[1].endswith("." + dependency))
                        if changed in self._resolve(candidate_path, name, dependency) or removed_match:
                            invalidated.add(candidate)
                            frontier.append(candidate)
                            break
        for stale in removed_keys | invalidated:
            self._summaries.pop(stale, None)
        analyzed = sorted(invalidated)
        for key in analyzed:
            self._summaries[key] = self._analyze(*key)
        return {
            "schema": SCHEMA, "path": path,
            "removed": sorted(self._key(*key) for key in removed_keys),
            "invalidated": sorted(self._key(*key) for key in invalidated),
            "analyzed": sorted(self._key(*key) for key in analyzed),
            "reused": sorted(self._key(*key) for key in
                             set(self._summaries) - set(analyzed)),
            "unknowns": [unknown for key in sorted(self._summaries)
                         for unknown in self._summaries[key]["unknowns"]],
        }

    def snapshot(self) -> dict:
        """Serializable incremental metadata; normalized trees remain reusable caches."""
        return {
            "schema": "pegrex.incremental-contracts-state.v1",
            "analyzer_version": ANALYZER_VERSION,
            "documents": self._documents,
            "summaries": [{"path": path, "function": function, "summary": summary}
                          for (path, function), summary in sorted(self._summaries.items())],
        }

    def restore(self, state: dict) -> None:
        """Restore metadata without deserializing executable objects or source text."""
        import json
        if state.get("schema") != "pegrex.incremental-contracts-state.v1":
            raise ValueError("unsupported incremental extractor state schema")
        if state.get("analyzer_version") != ANALYZER_VERSION:
            raise ValueError("incremental extractor analyzer version mismatch")
        documents = json.loads(json.dumps(state.get("documents", {})))
        for document in documents.values():
            for metadata in document.get("functions", {}).values():
                metadata["dependencies"] = tuple(metadata.get("dependencies", ()))
        summaries = {}
        for row in state.get("summaries", []):
            summaries[(str(Path(row["path"])), row["function"])] = row["summary"]
        self._documents = documents
        self._summaries = summaries
        self._sessions = {}

    def get(self, path: str, function: str) -> dict | None:
        """Implement get with the module's explicit API and failure semantics."""
        return self._summaries.get((str(Path(path)), function))

    def report(self) -> dict:
        """Implement report with the module's explicit API and failure semantics."""
        return {"schema": SCHEMA,
                "files": len(self._documents),
                "functions": len(self._summaries),
                "unknown_functions": sorted(self._key(*key) for key, value in self._summaries.items()
                                            if value["status"] != "ok"),
                "summaries": {self._key(*key): value
                              for key, value in sorted(self._summaries.items())}}
