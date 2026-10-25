"""Shared, content-addressed source analysis sessions.

One session owns one normalized syntax tree.  Consumers are lazy and memoized;
persistent entries are addressed by source content, parser/analyzer versions,
and normalized configuration rather than path or mtime.  Legacy analyzer
functions remain available independently and retain their public result shapes.
"""
from __future__ import annotations

import hashlib
import time
from typing import Any

from .cache import AnalysisCache
from .languages import get_language, normalize_language, parse_source
from .peg import Node

SESSION_VERSION = "shared-analysis-v1"


class AnalysisTimeout(TimeoutError):
    """A per-file analysis deadline expired; callers must report UNKNOWN."""


def _tree_data(value):
    if isinstance(value, Node):
        return {"tag": value.tag, "pos": value.pos, "endpos": value.endpos,
                "children": [_tree_data(child) for child in value.children]}
    if isinstance(value, list):
        return [_tree_data(child) for child in value]
    return value


def _tree_value(value):
    if isinstance(value, dict):
        return Node(value["tag"], value["pos"], value["endpos"],
                    [_tree_value(child) for child in value["children"]])
    if isinstance(value, list):
        return [_tree_value(child) for child in value]
    return value


class AnalysisSession:
    """Lazy shared analysis over immutable source text.

    ``configuration`` participates in every persistent cache identity.  The
    optional deadline is checked between analyzer stages; an expired stage is
    surfaced by :meth:`analyze` as ``status=unknown`` rather than a partial
    success.  No analyzer receives a path as a cache-key input.
    """

    def __init__(self, source: str, language: str = "python", *, path: str | None = None,
                 configuration: dict | None = None, cache: AnalysisCache | None = None,
                 timeout_ms: int | None = None, max_paths: int = 10_000) -> None:
        normalized = normalize_language(language)
        if normalized is None:
            raise ValueError(f"unsupported analysis language {language!r}")
        self.source = source
        self.language = normalized
        self.path = path
        self.configuration = dict(configuration or {})
        self.cache = cache
        self.timeout_ms = timeout_ms
        self.max_paths = max_paths
        self.digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        self._deadline = (time.monotonic() + timeout_ms / 1000
                          if timeout_ms is not None else None)
        self._values: dict[tuple, Any] = {}
        self.cache_hits = 0
        self.cache_misses = 0

    @property
    def spec(self):
        return get_language(self.language)

    def _check_deadline(self) -> None:
        if self._deadline is not None and time.monotonic() > self._deadline:
            raise AnalysisTimeout(
                f"{self.path or '<source>'}: analysis exceeded {self.timeout_ms}ms")

    def _version(self) -> dict:
        return {"session": SESSION_VERSION, "parser": self.spec.parser_version}

    def _config(self) -> dict:
        return {"language": self.language, "max_paths": self.max_paths,
                **self.configuration}

    def _persistent(self, analyzers: tuple[str, ...], producer):
        self._check_deadline()
        if self.cache is not None:
            payload = self.cache.get(self.source, analyzers,
                                     version=self._version(), configuration=self._config())
            if payload is not None:
                self.cache_hits += 1
                return payload
        self.cache_misses += 1
        value = producer()
        self._check_deadline()
        if self.cache is not None:
            self.cache.put(self.source, analyzers, value,
                           version=self._version(), configuration=self._config())
        return value

    @property
    def tree(self):
        """The sole normalized parse for this source/configuration session."""
        self._check_deadline()
        if "tree" not in self._values:
            data = self._persistent(
                ("parse", self.spec.parser, self.spec.parse_adapter),
                lambda: _tree_data(parse_source(self.language, self.source)))
            self._values["tree"] = _tree_value(data)
        return self._values["tree"]

    def cfg(self, entrypoint: str | None = None):
        """Return ``(cfg, condition_lowering)`` built from the shared tree."""
        key = ("cfg", entrypoint)
        self._check_deadline()
        if key not in self._values:
            if self.spec.contract_mode != "pipeline":
                raise NotImplementedError(f"CFG sessions unsupported for {self.language}")
            import pipeline
            from .cfg import CFGBuilder
            parse, tags, make_cond = pipeline.frontend_for(self.language)
            body = (parse(self.source, entrypoint, tree=self.tree)
                    if entrypoint is not None else parse(self.source, tree=self.tree))
            self._values[key] = (CFGBuilder(tags).build(body), make_cond(self.source))
        return self._values[key]

    def contracts(self, entrypoint: str | None = None):
        key = ("contracts", entrypoint)
        self._check_deadline()
        if key not in self._values:
            from .languages import extract_contract_pairs
            name = f"contracts:{entrypoint or '<module>'}"
            rows = self._persistent(
                (name, SESSION_VERSION),
                lambda: [[sorted(map(str, guards)), outcome] for guards, outcome in
                         extract_contract_pairs(self.language, self.source,
                                                entrypoint=entrypoint, tree=self.tree,
                                                max_paths=self.max_paths,
                                                timeout_ms=self.timeout_ms)])
            self._values[key] = [(frozenset(guards), outcome) for guards, outcome in rows]
        return self._values[key]

    @property
    def call_graph(self):
        self._check_deadline()
        if "call_graph" not in self._values:
            from .callgraph import CallGraph, build_call_graph

            def produce():
                graph = build_call_graph(self.source, self.language, tree=self.tree)
                return {"functions": {name: {"line": row["line"],
                                             "calls": sorted(row["calls"])}
                                      for name, row in graph.functions.items()},
                        "edges": sorted(map(list, graph.edges))}

            data = self._persistent(("callgraph", SESSION_VERSION), produce)
            graph = CallGraph()
            graph.functions = {name: {"line": row["line"], "calls": set(row["calls"])}
                               for name, row in data["functions"].items()}
            graph.edges = {tuple(edge) for edge in data["edges"]}
            self._values["call_graph"] = graph
        return self._values["call_graph"]

    @property
    def complexity(self):
        self._check_deadline()
        if "complexity" not in self._values:
            from .cognitive import cognitive_complexity
            self._values["complexity"] = self._persistent(
                ("complexity", SESSION_VERSION),
                lambda: cognitive_complexity(self.source, self.language, tree=self.tree))
        return self._values["complexity"]

    @property
    def security(self):
        """SAST and taint findings over the shared tree."""
        self._check_deadline()
        if "security" not in self._values:
            from tools.secaudit import audit_source
            self._values["security"] = self._persistent(
                ("sast", "taint", SESSION_VERSION),
                lambda: audit_source(self.source, self.language, tree=self.tree))
        return self._values["security"]

    def synthesize_tests(self, coverage_lines, function_name: str, unroll: int = 2):
        """Synthesize tests from the session CFG without another source parse."""
        self._check_deadline()
        key = ("tests", tuple(sorted(coverage_lines)), function_name, unroll)
        if key not in self._values:
            from .testsynth import synthesize_tests
            cfg, condition = self.cfg(function_name)
            self._values[key] = synthesize_tests(
                cfg, condition, set(coverage_lines), function_name, unroll=unroll)
        return self._values[key]

    def analyze(self, analyzers=("contracts", "call_graph", "complexity", "security")) -> dict:
        """Run selected consumers and expose per-analyzer resource UNKNOWNs."""
        results = {}
        for name in analyzers:
            try:
                value = self.contracts() if name == "contracts" else getattr(self, name)
                if name == "contracts":
                    value = [[sorted(map(str, guards)), outcome] for guards, outcome in value]
                elif name == "call_graph":
                    value = {"functions": {key: {"line": row["line"],
                                                 "calls": sorted(row["calls"])}
                                           for key, row in value.functions.items()},
                             "edges": sorted(map(list, value.edges))}
                results[name] = {"status": "ok", "data": value}
            except AnalysisTimeout as exc:
                results[name] = {"status": "unknown", "reason": str(exc),
                                 "resource": "per-file-timeout"}
            except Exception as exc:
                from .paths import PathExplosion
                if not isinstance(exc, PathExplosion):
                    raise
                results[name] = {"status": "unknown", "reason": str(exc),
                                 "resource": "path-count-cap"}
        return {"schema": "pegrex.analysis-session.v1", "language": self.language,
                "source_sha256": self.digest, "results": results}
