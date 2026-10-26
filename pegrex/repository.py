"""Incremental repository indexing over shared, content-addressed ASTs.

Paths locate working-tree documents; they never define semantic cache identity.
Parse and analysis failures are retained as UNKNOWN coverage, and a broken new
revision cannot replace the last valid contract snapshot with a clean result.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

from .cache import AnalysisCache
from .incremental import ANALYZER_VERSION, IncrementalContractExtractor
from .languages import detect_language, get_language, parser_provenance
from .sessions import AnalysisSession

SCHEMA = "pegrex.repository-index.v1"
STATE_SCHEMA = "pegrex.repository-index-state.v1"
_IGNORED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".pegrex-cache", "__pycache__", "node_modules",
    "dist", "build", ".venv", "venv",
}


def _digest(source: str) -> str:
    return hashlib.sha256(source.encode("utf-8")).hexdigest()


class RepositoryIndex:
    def __init__(self, root: str | Path, *, configuration: dict | None = None,
                 cache: AnalysisCache | None = None, max_paths: int = 10_000,
                 timeout_ms: int | None = None, max_file_bytes: int = 2_000_000) -> None:
        self.root = Path(root).resolve()
        self.configuration = dict(configuration or {})
        self.cache = cache
        self.max_paths = max_paths
        self.timeout_ms = timeout_ms
        self.max_file_bytes = max_file_bytes
        self.tree_cache: dict = {}
        self.extractor = IncrementalContractExtractor(
            max_paths=max_paths, timeout_ms=timeout_ms, tree_cache=self.tree_cache)
        self.entries: dict[str, dict] = {}
        self._sessions: dict[str, AnalysisSession] = {}
        self._last_scan = {"changed": [], "removed": [], "reused": [],
                           "analyzed": [], "unknowns": []}

    def _path(self, path: str | Path) -> tuple[Path, str]:
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = self.root / candidate
        resolved = candidate.resolve()
        try:
            relative = resolved.relative_to(self.root).as_posix()
        except ValueError as exc:
            raise ValueError(f"repository path escapes root: {path!r}") from exc
        return resolved, relative

    def _discover(self) -> dict[str, Path]:
        discovered: dict[str, Path] = {}
        if not self.root.exists():
            return discovered
        for directory, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = sorted(name for name in dirnames
                                 if name not in _IGNORED_DIRECTORIES
                                 and not (Path(directory) / name).is_symlink())
            for filename in sorted(filenames):
                path = Path(directory) / filename
                if path.is_symlink() or detect_language(path) is None:
                    continue
                relative = path.relative_to(self.root).as_posix()
                discovered[relative] = path
        return discovered

    def update_file(self, path: str | Path, source: str | None = None,
                    language: str | None = None) -> dict:
        """Implement update file with the module's explicit API and failure semantics."""
        absolute, relative = self._path(path)
        previous = self.entries.get(relative, {})
        try:
            resolved_language = detect_language(absolute, language)
        except ValueError as exc:
            return self._unknown(relative, previous, None, str(exc))
        if resolved_language is None:
            entry = {
                "path": relative, "status": "skipped", "language": None,
                "reason": "unsupported-language", "unknowns": [], "stale": False,
            }
            self.entries[relative] = entry
            return entry
        try:
            if source is None:
                if absolute.stat().st_size > self.max_file_bytes:
                    raise ValueError(f"file exceeds {self.max_file_bytes} byte budget")
                source = absolute.read_text(encoding="utf-8")
            elif len(source.encode("utf-8")) > self.max_file_bytes:
                raise ValueError(f"source exceeds {self.max_file_bytes} byte budget")
        except Exception as exc:
            return self._unknown(relative, previous, resolved_language,
                                 f"{type(exc).__name__}: {exc}")
        digest = _digest(source)
        if (previous.get("source_sha256") == digest
                and previous.get("status") in {"ok", "skipped"}
                and not previous.get("stale")):
            reused = dict(previous)
            reused["analyzed"] = []
            reused["reused"] = previous.get("function_keys", [])
            self.entries[relative] = reused
            return reused

        session = AnalysisSession(
            source, resolved_language, path=relative, configuration=self.configuration,
            cache=self.cache, timeout_ms=self.timeout_ms, max_paths=self.max_paths,
            tree_cache=self.tree_cache)
        try:
            session.tree  # the only repository parse; the extractor reuses this tree
        except Exception as exc:
            return self._unknown(relative, previous, resolved_language,
                                 f"{type(exc).__name__}: {exc}", digest)
        try:
            update = self.extractor.update(relative, source, resolved_language)
        except Exception as exc:
            # Some parsers produce error nodes instead of raising; the
            # inventory/CFG layer is the next explicit rejection boundary.
            return self._unknown(relative, previous, resolved_language,
                                 f"{type(exc).__name__}: {exc}", digest)
        self._sessions[relative] = session
        unknowns = list(update["unknowns"])
        entry = {
            "path": relative, "status": "unknown" if unknowns else "ok",
            "language": resolved_language, "source_sha256": digest,
            "indexed_source_sha256": digest, "stale": False,
            "parser": parser_provenance(resolved_language),
            "granularity": update["granularity"],
            "changed": update["changed"], "removed": update["removed"],
            "invalidated": update["invalidated"], "analyzed": update["analyzed"],
            "reused": update["reused"],
            "function_keys": sorted(update["summaries"]),
            "unknowns": unknowns,
        }
        self.entries[relative] = entry
        return entry

    def _unknown(self, relative: str, previous: dict, language: str | None,
                 reason: str, digest: str | None = None) -> dict:
        # Keep the prior valid summary identity visible, but mark it stale. A
        # caller can never mistake the failed revision for a newly proved one.
        entry = dict(previous)
        entry.update({
            "path": relative, "status": "unknown", "language": language,
            "source_sha256": digest, "stale": bool(previous),
            "indexed_source_sha256": previous.get("indexed_source_sha256"),
            "analyzed": [], "reused": previous.get("function_keys", []),
            "unknowns": [reason],
        })
        self.entries[relative] = entry
        self._sessions.pop(relative, None)
        return entry

    def remove_file(self, path: str | Path) -> dict:
        """Implement remove file with the module's explicit API and failure semantics."""
        _, relative = self._path(path)
        result = self.extractor.remove(relative)
        self.entries.pop(relative, None)
        self._sessions.pop(relative, None)
        return result

    def scan(self) -> dict:
        """Implement scan with the module's explicit API and failure semantics."""
        discovered = self._discover()
        removed = sorted(set(self.entries) - set(discovered))
        removal_results = [self.remove_file(relative) for relative in removed]
        changed, reused, analyzed, unknowns = [], [], [], []
        for relative, path in sorted(discovered.items()):
            entry = self.update_file(path)
            if entry.get("analyzed"):
                changed.append(relative)
                analyzed.extend(entry["analyzed"])
            else:
                reused.append(relative)
            unknowns.extend(f"{relative}: {reason}" for reason in entry.get("unknowns", []))
        analyzed.extend(key for result in removal_results for key in result["analyzed"])
        unknowns.extend(f"{relative}: {reason}" for result, relative in
                        zip(removal_results, removed) for reason in result["unknowns"])
        self._last_scan = {"changed": changed, "removed": removed, "reused": reused,
                           "analyzed": sorted(set(analyzed)), "unknowns": unknowns}
        return self.report()

    def tree(self, path: str | Path):
        """Implement tree with the module's explicit API and failure semantics."""
        _, relative = self._path(path)
        if relative not in self._sessions:
            raise KeyError(f"no current parsed session for {relative!r}")
        return self._sessions[relative].tree

    def get(self, path: str | Path, function: str) -> dict | None:
        """Implement get with the module's explicit API and failure semantics."""
        _, relative = self._path(path)
        return self.extractor.get(relative, function)

    def report(self) -> dict:
        """Implement report with the module's explicit API and failure semantics."""
        entries = [self.entries[key] for key in sorted(self.entries)]
        return {
            "schema": SCHEMA, "analyzer_version": ANALYZER_VERSION,
            "files": len(entries),
            "indexed": sum(row["status"] == "ok" for row in entries),
            "unknown": sum(row["status"] == "unknown" for row in entries),
            "skipped": sum(row["status"] == "skipped" for row in entries),
            "functions": sum(len(row.get("function_keys", [])) for row in entries),
            "shared_ast_entries": len(self.tree_cache),
            "entries": entries, "last_scan": self._last_scan,
            "unknowns": [f"{row['path']}: {reason}" for row in entries
                         for reason in row.get("unknowns", [])],
        }

    def save(self, path: str | Path) -> dict:
        """Implement save with the module's explicit API and failure semantics."""
        destination = Path(path)
        payload = {
            "schema": STATE_SCHEMA, "analyzer_version": ANALYZER_VERSION,
            "configuration": self.configuration, "max_paths": self.max_paths,
            "entries": self.entries, "extractor": self.extractor.snapshot(),
        }
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        temporary.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n",
                             encoding="utf-8")
        temporary.replace(destination)
        return {"schema": STATE_SCHEMA, "path": str(destination),
                "files": len(self.entries)}

    @classmethod
    def load(cls, root: str | Path, path: str | Path, **kwargs) -> "RepositoryIndex":
        """Implement load with the module's explicit API and failure semantics."""
        state = json.loads(Path(path).read_text(encoding="utf-8"))
        if state.get("schema") != STATE_SCHEMA:
            raise ValueError("unsupported repository index state schema")
        if state.get("analyzer_version") != ANALYZER_VERSION:
            raise ValueError("repository index analyzer version mismatch")
        configuration = kwargs.get("configuration")
        if configuration is not None and configuration != state["configuration"]:
            raise ValueError("repository index configuration mismatch")
        kwargs["configuration"] = state["configuration"]
        kwargs["max_paths"] = state["max_paths"]
        index = cls(root, **kwargs)
        for relative in state["entries"]:
            if Path(relative).is_absolute() or ".." in Path(relative).parts:
                raise ValueError(f"unsafe indexed path {relative!r}")
        index.entries = state["entries"]
        index.extractor.restore(state["extractor"])
        return index
