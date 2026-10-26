from __future__ import annotations

import pathlib

from . import cache, contract, coverage, extension, workflow
from .budget import Budget
from .callgraph import CallGraph
from .callgraph import build_call_graph as _build_call_graph
from .bisim import bisimilar
from .cfg import CFG, CFGBuilder, TagSpec
from .coverage import coverage_gaps, parse_gocover, parse_lcov
from .gramir import lift, lift_grammar, lower, to_dsl
from .induce import fitness, induce, mutate
from .mini_llm import NGramLM
from .parallel import find_pragmas, race_findings
from .paths import PathEnumerator, PathFormula, linearize
from .patterns import Pattern, match, scan
from .recursion import analyze_recursion
from .smt import Backend, auto_feasible, entails, learn
from .summaries import compose, expand_calls, path_summaries
from .sym import *
from .testsynth import SynthesizedTest, synthesize_tests
from .tokenizer import Token, token_stream, tokenize

ROOT = pathlib.Path(__file__).resolve().parent.parent


def audit(path: str, lang: str | None = None) -> list[dict]:
    """Compatibility adapter: stable-core audit result -> historical findings list."""
    result = get_engine().audit(path, lang)
    keys = ("id", "severity", "confidence", "line", "evidence",
            "message", "kind", "function")
    return [{key: finding.get(key) for key in keys}
            for finding in (result.data or [])]


def spec(source: str, name: str, out_dir: str = "specs",
         views=None, analyzers=None) -> dict:
    """Multi-opus AI spec schema -> dict (also written to out_dir)."""
    import json as _json
    import sys as _sys
    if str(ROOT) not in _sys.path:
        _sys.path.insert(0, str(ROOT))
    from tools.mkspec import core as mkspec
    ctx, facts = mkspec.run_analyzers(source, analyzers)
    results = mkspec.run_opus(ctx, facts, views)
    rendered = mkspec.render_spec(ctx, facts, results, "full", name)
    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / f"{name}.spec.json").write_text(_json.dumps(rendered, indent=1), encoding="utf-8")
    return rendered


from .languages import detect_language, get_language, normalize_language
from .core import get_engine


def contracts(path: str, lang: str | None = None) -> list:
    """Compatibility API for path contracts.

    The stable core owns language selection, capability checks, result models,
    and canonical contract identity. This public function preserves the legacy
    ``[(frozenset(guards), outcome)]`` return shape for existing clients.
    """
    resolved = detect_language(path, lang, default="python")
    result = get_engine().contracts_file(path, resolved)
    if result.status.value == "error":
        raise RuntimeError("contract extraction failed: " + "; ".join(result.unknowns))
    return [(frozenset(row["constraints"]), row["outcome"])
            for row in (result.data or [])]


def coverage(path: str, lcov_path: str, lang: str = "python") -> dict:
    """Coverage overlay + gaps: path_coverage per path, gaps with constraints."""
    import pipeline
    from .coverage import (covered_lines, parse_lcov, path_coverage,
                           coverage_gaps)
    src = pathlib.Path(path).read_text(encoding="utf-8")
    cov = list(parse_lcov(pathlib.Path(lcov_path).read_text(encoding="utf-8")).values())
    cov_lines = covered_lines(cov[0]) if cov else set()
    parse, tags, mk = pipeline.frontend_for(lang)
    cfg = CFGBuilder(tags).build(parse(src))
    paths = PathEnumerator(cfg, unroll=2).enumerate()
    return {"paths": path_coverage(cfg, paths, cov_lines),
            "gaps": coverage_gaps(cfg, mk(src), cov_lines)}


def gaps(source: str, lcov: str, lang: str = "python") -> list[dict]:
    """Coverage gaps with constraint context."""
    import pipeline
    src = pathlib.Path(source).read_text(encoding="utf-8")
    cov = list(parse_lcov(pathlib.Path(lcov).read_text(encoding="utf-8")).values())
    cov_lines = __import__("pegrex.coverage", fromlist=["covered_lines"]
                           ).covered_lines(cov[0]) if cov else set()
    parse, tags, mk = pipeline.frontend_for(lang)
    cfg = CFGBuilder(tags).build(parse(src))
    return coverage_gaps(cfg, mk(src), cov_lines)


def synthesize_tests_from_coverage(source: str, lcov: str,
                                   fn_name: str | None = None) -> list:
    """Synthesize pytest tests from coverage gaps without shadowing program synthesis."""
    from .coverage import covered_lines
    import pipeline
    src = pathlib.Path(source).read_text(encoding="utf-8")
    cov = list(parse_lcov(pathlib.Path(lcov).read_text(encoding="utf-8")).values())
    cov_lines = covered_lines(cov[0]) if cov else set()
    parse, tags, mk = pipeline.frontend_for("python")
    cfg = CFGBuilder(tags).build(parse(src))
    return synthesize_tests(cfg, mk(src), cov_lines,
                            fn_name or pathlib.Path(source).stem)


# Explicit compatibility alias; ``synthesize`` remains the program-synthesis API.
synthesize_from_coverage = synthesize_tests_from_coverage


def call_graph(source: str, lang: str = "python") -> "CallGraph":
    """Legacy CallGraph view backed by the stable-core operation result."""
    result = get_engine().call_graph(source, lang)
    graph = CallGraph()
    graph.functions = {name: {"line": 0, "calls": set()} for name in result.data["functions"]}
    graph.edges = {tuple(edge) for edge in result.data["edges"]}
    for caller, callee in graph.edges:
        graph.functions.setdefault(caller, {"line": 0, "calls": set()})["calls"].add(callee)
        graph.functions.setdefault(callee, {"line": 0, "calls": set()})
    return graph


def rag_index(paths) -> "object":
    """rag index(paths): see module docstring."""
    from .rag import build_index
    return build_index(paths)


def rag_search(index, query: str, k: int = 5) -> list:
    """rag search(index, query, k): see module docstring."""
    from .rag import retrieve
    return retrieve(index, query, k)


def budget_check(path: str, max_loc: int = 300,
                 max_function_lines: int = 40) -> Budget:
    """budget check(path, max_loc, max_function_lines): see module docstring."""
    b = Budget(max_loc=max_loc, max_function_lines=max_function_lines)
    return b.check(path, pathlib.Path(path).read_text(encoding="utf-8"))


def races(src: str) -> list[str]:
    """races(src): see module docstring."""
    return race_findings(src)


def recursion_report(fn_name: str, body, src: str):
    """recursion report(fn_name, body, src): see module docstring."""
    return analyze_recursion(fn_name, body, src)


def mir_cfg(mir_text: str) -> CFG:
    """mir cfg(mir_text): see module docstring."""
    import sys as _sys
    if str(ROOT) not in _sys.path:
        _sys.path.insert(0, str(ROOT))
    import pipeline
    _, cfg_from_mir, _ = pipeline.mir_frontend()
    return cfg_from_mir(mir_text)


def repo_index(root: str, out: str = "repo.index.json") -> dict:
    """repo index(root, out): see module docstring."""
    import sys as _sys
    if str(ROOT) not in _sys.path:
        _sys.path.insert(0, str(ROOT))
    from tools.repokit import repo_index as _ri
    return _ri(root, out=out)


def bundle(source: str, out: str | None = None) -> dict:
    """bundle(source, out): see module docstring."""
    import sys as _sys
    if str(ROOT) not in _sys.path:
        _sys.path.insert(0, str(ROOT))
    from tools.repokit import verification_bundle
    return verification_bundle(source, out=out)


from .acp import AcpServer

from .circuit import check_circuit
from .egraphs import EGraph
from .formalize import check_invariant as spec_check, formalize
from .legal import obligations_as_constraints, parse_clauses
from .metaengine import build_system
from .modelcheck import check_invariant
from .ownership import borrow_check
from .passverify import verify_pass
from .poc import codegen_gate, poc_template
from .protocol import verify_protocol
from .proofrepair import ast_fingerprint, diff_blocks
from .synthesize import synthesize
from .transpiler import transpile
from .wp import wp_assign, wp_cond, wp_path
from .abstract import interval_analysis

from .mcp import MCPRouter, MCPServer, engine_tools

from .ci import analyze_pipeline as ci_scan
from .sca import scan as osv_scan
from .export import export as export_findings
