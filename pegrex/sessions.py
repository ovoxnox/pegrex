"""Shared, content-addressed source analysis sessions.

One session owns one normalized syntax tree.  Consumers are lazy and memoized;
persistent entries are addressed by source content, parser/analyzer versions,
and normalized configuration rather than path or mtime.  Legacy analyzer
functions remain available independently and retain their public result shapes.
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any

from .cache import AnalysisCache
from .limits import (DEFAULT_ANALYSIS_TIMEOUT_MS, MAX_SOURCE_BYTES,
                     MAX_AST_NODES, MAX_ANALYSIS_OUTPUT_BYTES, MAX_ANALYSIS_PATHS)
from .languages import get_language, normalize_language, parse_source
from .peg import Node

SESSION_VERSION = "shared-analysis-v2"


class AnalysisTimeout(TimeoutError):
    """A per-file analysis deadline expired; callers must report UNKNOWN."""


class AnalysisResourceLimit(ValueError):
    """A hard analysis input, tree, or output budget was exceeded."""


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
                 timeout_ms: int | None = None,
                 max_paths: int | None = None,
                 tree_cache: dict | None = None,
                 max_source_bytes: int | None = None,
                 max_ast_nodes: int | None = None,
                 max_output_bytes: int | None = None,
                 max_solver_calls: int | None = None,
                 mode: str | None = None) -> None:
        normalized = normalize_language(language)
        if normalized is None:
            raise ValueError(f"unsupported analysis language {language!r}")
        if not isinstance(source, str):
            raise TypeError("source must be text")
        from .performance import audit_mode
        if mode is not None:
            profile = audit_mode(mode)
            mode_limits = {"timeout_ms": int(profile.max_seconds * 1000),
                           "max_paths": profile.max_paths,
                           "max_source_bytes": min(MAX_SOURCE_BYTES, 1_000_000) if mode == "fast" else MAX_SOURCE_BYTES,
                           "max_ast_nodes": 20_000 if mode == "fast" else 250_000,
                           "max_output_bytes": 1_000_000 if mode == "fast" else 8_000_000,
                           "max_solver_calls": profile.max_solver_calls}
            supplied = {"timeout_ms": timeout_ms, "max_paths": max_paths,
                        "max_source_bytes": max_source_bytes, "max_ast_nodes": max_ast_nodes,
                        "max_output_bytes": max_output_bytes, "max_solver_calls": max_solver_calls}
            limits = {key: min(value, mode_limits[key]) if value is not None else mode_limits[key]
                      for key, value in supplied.items()}
        else:
            limits = {"timeout_ms": DEFAULT_ANALYSIS_TIMEOUT_MS if timeout_ms is None else timeout_ms,
                      "max_paths": MAX_ANALYSIS_PATHS if max_paths is None else max_paths,
                      "max_source_bytes": MAX_SOURCE_BYTES if max_source_bytes is None else max_source_bytes,
                      "max_ast_nodes": MAX_AST_NODES if max_ast_nodes is None else max_ast_nodes,
                      "max_output_bytes": MAX_ANALYSIS_OUTPUT_BYTES if max_output_bytes is None else max_output_bytes,
                      "max_solver_calls": 5_000 if max_solver_calls is None else max_solver_calls}
        if limits["timeout_ms"] is not None and limits["timeout_ms"] < 0:
            raise ValueError("analysis timeout must be non-negative")
        if any(limits[key] < 1 for key in ("max_paths", "max_source_bytes", "max_ast_nodes", "max_output_bytes", "max_solver_calls")):
            raise ValueError("analysis resource limits must be positive")
        self.source = source
        self.mode = mode or "default"
        self.max_source_bytes = limits["max_source_bytes"]
        self.max_ast_nodes = limits["max_ast_nodes"]
        self.max_output_bytes = limits["max_output_bytes"]
        self.max_solver_calls = limits["max_solver_calls"]
        self._input_error = None
        if len(source.encode("utf-8")) > self.max_source_bytes:
            self._input_error = AnalysisResourceLimit(
                f"source exceeds input budget of {self.max_source_bytes} bytes")
        self.language = normalized
        self.path = path
        self.configuration = dict(configuration or {})
        self.cache = cache
        self.tree_cache = tree_cache
        self.timeout_ms = limits["timeout_ms"]
        self.max_paths = limits["max_paths"]
        self.digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
        self._deadline = (time.monotonic() + timeout_ms / 1000
                          if timeout_ms is not None else None)
        self._values: dict[tuple, Any] = {}
        self.cache_hits = 0
        self.cache_misses = 0

    @property
    def spec(self):
        """Implement spec with the module's explicit API and failure semantics."""
        return get_language(self.language)

    def _check_deadline(self) -> None:
        if self._input_error is not None:
            raise self._input_error
        if self._deadline is not None and time.monotonic() > self._deadline:
            raise AnalysisTimeout(
                f"{self.path or '<source>'}: analysis exceeded {self.timeout_ms}ms")

    def _version(self) -> dict:
        return {"session": SESSION_VERSION, "parser": self.spec.parser_version}

    def _config(self) -> dict:
        return {"language": self.language, "mode": self.mode,
                "timeout_ms": self.timeout_ms, "max_paths": self.max_paths,
                "max_source_bytes": self.max_source_bytes,
                "max_ast_nodes": self.max_ast_nodes,
                "max_output_bytes": self.max_output_bytes,
                "max_solver_calls": self.max_solver_calls,
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
        """Return the normalized parse tree after enforcing node limits."""
        self._check_deadline()
        if "tree" not in self._values:
            identity = json.dumps(self._config(), sort_keys=True, separators=(",", ":"),
                                  default=str)
            key = (self.digest, self.spec.parser, self.spec.parser_version,
                   self.spec.parse_adapter, identity)
            cached = self.tree_cache.get(key) if self.tree_cache is not None else None
            if cached is not None:
                tree = cached
            else:
                data = self._persistent(
                    ("parse", self.spec.parser, self.spec.parse_adapter),
                    lambda: _tree_data(parse_source(self.language, self.source)))
                tree = _tree_value(data)
            nodes = 0
            pending = [tree]
            while pending:
                current = pending.pop()
                if isinstance(current, Node):
                    nodes += 1
                    if nodes > self.max_ast_nodes:
                        raise AnalysisResourceLimit(
                            f"syntax tree exceeds node budget of {self.max_ast_nodes}")
                    pending.extend(current.children)
                elif isinstance(current, list):
                    pending.extend(current)
            self._values["tree"] = tree
            if self.tree_cache is not None and cached is None:
                self.tree_cache[key] = tree
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
        """Implement contracts with the module's explicit API and failure semantics."""
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
        """Implement call graph with the module's explicit API and failure semantics."""
        self._check_deadline()
        if "call_graph" not in self._values:
            from .callgraph import CallGraph, build_call_graph

            def produce():
                """Implement produce with the module's explicit API and failure semantics."""
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
        """Implement complexity with the module's explicit API and failure semantics."""
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
        """Run selected consumers with shared budgets and per-stage profiling."""
        from .performance import AnalysisProfile, SolverBudgetExceeded, analysis_scope
        profile = AnalysisProfile()
        results = {}
        with analysis_scope(profile, max_solver_calls=self.max_solver_calls) as solver_budget:
            for name in analyzers:
                try:
                    profile.count("analyzer_calls")
                    def execute():
                        return self.contracts() if name == "contracts" else getattr(self, name)
                    value = profile.measure(name, execute)
                    if name == "contracts":
                        value = [[sorted(map(str, guards)), outcome] for guards, outcome in value]
                        profile.count("contract_paths", len(value))
                    elif name == "call_graph":
                        value = {"functions": {key: {"line": row["line"],
                                                     "calls": sorted(row["calls"])}
                                               for key, row in value.functions.items()},
                                 "edges": sorted(map(list, value.edges))}
                        profile.count("call_graph_edges", len(value["edges"]))
                    elif name == "security" and isinstance(value, list):
                        profile.count("security_findings", len(value))
                    if isinstance(value, dict):
                        solver_calls = value.get("solver_calls")
                        if isinstance(solver_calls, int) and solver_calls >= 0:
                            profile.count("solver_calls_reported_by_analyzer", solver_calls)
                    results[name] = {"status": "ok", "data": value}
                except SolverBudgetExceeded as exc:
                    results[name] = {"status": "unknown", "reason": str(exc),
                                     "resource": "solver-call-cap"}
                except AnalysisResourceLimit as exc:
                    results[name] = {"status": "unknown", "reason": str(exc),
                                     "resource": "input-or-analysis-size-cap"}
                except AnalysisTimeout as exc:
                    results[name] = {"status": "unknown", "reason": str(exc),
                                     "resource": "per-file-timeout"}
                except Exception as exc:
                    from .paths import PathExplosion
                    if isinstance(exc, (RecursionError, MemoryError)):
                        results[name] = {"status": "unknown", "reason": "analysis resource exhaustion",
                                         "resource": "runtime-resource-limit"}
                        continue
                    if not isinstance(exc, PathExplosion):
                        raise
                    results[name] = {"status": "unknown", "reason": str(exc),
                                     "resource": "path-count-cap"}
        report = {"schema": "pegrex.analysis-session.v1", "language": self.language,
                  "mode": self.mode, "source_sha256": self.digest,
                  "resource_limits": {"timeout_ms": self.timeout_ms, "max_paths": self.max_paths,
                                      "max_source_bytes": self.max_source_bytes,
                                      "max_ast_nodes": self.max_ast_nodes,
                                      "max_output_bytes": self.max_output_bytes,
                                      "max_solver_calls": self.max_solver_calls},
                  "profile": profile.snapshot(),
                  "solver_budget": {"max_calls": self.max_solver_calls, "calls": solver_budget["calls"]},
                  "results": results}
        try:
            encoded_size = len(json.dumps(report, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        except (TypeError, ValueError, RecursionError):
            return {"schema": "pegrex.analysis-session.v1", "language": self.language,
                    "mode": self.mode, "source_sha256": self.digest,
                    "resource_limits": report["resource_limits"],
                    "results": {name: {"status": "unknown", "resource": "output-serialization",
                                        "reason": "analysis result could not be safely serialized"}
                                for name in analyzers}}
        if encoded_size > self.max_output_bytes:
            return {"schema": "pegrex.analysis-session.v1", "language": self.language,
                    "mode": self.mode, "source_sha256": self.digest,
                    "resource_limits": report["resource_limits"],
                    "results": {name: {"status": "unknown", "resource": "output-size-cap",
                                        "reason": f"analysis report exceeds {self.max_output_bytes} bytes"}
                                for name in analyzers}}
        return report

