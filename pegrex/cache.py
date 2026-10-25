"""
cache

Content-addressed analysis cache and dependency-aware incremental summaries.
Keys include full source digests, implementation versions, and normalized
configuration; file paths and mtimes never determine correctness."""

from __future__ import annotations

import hashlib
import json
import pathlib

from .contract import StructuralError


class AnalysisCache:
    """AnalysisCache - see module docstring."""
    def __init__(self, root: str | pathlib.Path = ".pegrex-cache") -> None:
        self.root = pathlib.Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def key(self, source: str, analyzers: tuple[str, ...], *,
            version: str = "v1", configuration: dict | None = None) -> pathlib.Path:
        """Content + implementation + configuration address; paths/mtimes are irrelevant."""
        content = hashlib.sha256(source.encode("utf-8")).hexdigest()
        identity = json.dumps({"analyzers": sorted(analyzers), "version": version,
                               "configuration": configuration or {}},
                              sort_keys=True, separators=(",", ":"), default=str)
        config = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        return self.root / f"{content}-{config}.json"

    def get(self, source: str, analyzers: tuple[str, ...], **identity):
        p = self.key(source, analyzers, **identity)
        if p.exists():
            return json.loads(p.read_text())
        return None

    def put(self, source: str, analyzers: tuple[str, ...], payload: dict, **identity) -> None:
        path = self.key(source, analyzers, **identity)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, sort_keys=True))
        temporary.replace(path)


class IncrementalSummaryCache:
    """Invalidate a changed file and every transitive reverse dependent.

    ``update`` records content, dependencies, and implementation identity.  A
    summary is valid only for the exact recursive dependency revision that
    produced it.  Paths identify dependency edges, never cache correctness.
    """

    def __init__(self) -> None:
        self._documents: dict[str, dict] = {}
        self._summaries: dict[str, dict] = {}

    @staticmethod
    def _identity(source: str, dependencies, version: str,
                  configuration: dict | None) -> str:
        payload = {
            "source": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "dependencies": sorted(dependencies),
            "version": version,
            "configuration": configuration or {},
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                             default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def update(self, path: str, source: str, *, dependencies=(),
               version: str = "v1", configuration: dict | None = None) -> set[str]:
        path = str(path)
        document = {
            "digest": hashlib.sha256(source.encode("utf-8")).hexdigest(),
            "dependencies": tuple(sorted(map(str, dependencies))),
            "version": version,
            "configuration": configuration or {},
        }
        changed = self._documents.get(path) != document
        self._documents[path] = document
        if not changed:
            return set()
        invalidated = {path}
        frontier = [path]
        while frontier:
            target = frontier.pop()
            for candidate, candidate_doc in self._documents.items():
                if target in candidate_doc["dependencies"] and candidate not in invalidated:
                    invalidated.add(candidate)
                    frontier.append(candidate)
        for stale in invalidated:
            self._summaries.pop(stale, None)
        return invalidated

    def _revision(self, path: str, active: frozenset[str] = frozenset()) -> str:
        if path in active:
            raise ValueError(f"cyclic summary dependencies involving {path!r}")
        doc = self._documents[path]
        payload = {
            "document": doc,
            "dependencies": [
                [dependency, self._revision(dependency, active | {path})]
                if dependency in self._documents else [dependency, "missing"]
                for dependency in doc["dependencies"]
            ],
        }
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                             default=str).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def put(self, path: str, summary: dict) -> None:
        path = str(path)
        if path not in self._documents:
            raise KeyError(f"update {path!r} before storing its summary")
        self._summaries[path] = {"revision": self._revision(path), "summary": summary}

    def get(self, path: str) -> dict | None:
        path = str(path)
        entry = self._summaries.get(path)
        if entry is None or path not in self._documents:
            return None
        if entry["revision"] != self._revision(path):
            self._summaries.pop(path, None)
            return None
        return entry["summary"]


def memoized_compose(compose_fn):
    """compose(caller_contract, callee, callee_contract, param, arg) with a
    per-call-site contract cache: whole-program analysis becomes near-linear
    on shared callees."""
    cache: dict = {}

    def wrapper(caller, callee_name, callee_contract, param, arg):
        """wrapper(caller, callee_name, callee_contract, param, arg)"""
        key = (callee_name, param, arg,
               hash(repr(callee_contract)) & 0xFFFFFFFF)
        if key not in cache:
            cache[key] = compose_fn([(frozenset(), f"{callee_name}({arg})")],
                                    callee_name, callee_contract, param, arg)
        return cache[key]

    return wrapper
