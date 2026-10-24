"""
mkspec Core:

║  Analyzer × Opus × Template  →  rich AI spec schemas. 
║  Open for extension (plugins), closed for modification (registries)."""

from __future__ import annotations

import argparse
import dataclasses
import datetime
import hashlib
import importlib.util
import json
import pathlib
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Protocol

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

import pegrex

# ══ Registries ── Single Responsibility: discovery only
ANALYZERS: dict[str, Callable[["AnalysisContext"], Iterable["Finding"]]] = {}
OPUS: dict[str, Callable[["AnalysisContext", list["Finding"]], dict]] = {}


@dataclass
class Finding:
    analyzer: str
    check_id: str
    # CRITICAL | HIGH | MEDIUM | LOW | INFO
    severity: str
    line: int
    evidence: str
    symbol: str = ""
    metric: dict = field(default_factory=dict)
    fix: str = ""


@dataclass
class AnalysisContext:
    """Everything an analyzer may touch. Nothing else exists."""
    path: pathlib.Path
    lang: str | None
    src: str
    tree: object | None


def analyzer(name: str):
    def deco(fn):
        ANALYZERS[name] = fn
        return fn
    return deco


def opus(name: str):
    """An opus = a perspective that turns findings into agent tasks."""
    def deco(fn):
        OPUS[name] = fn
        return fn
    return deco


# ═══ Analysis pipeline
_TSMODS = {".py": ("python", "tree_sitter_python", "language"),
           ".go": ("go", "tree_sitter_go", "language"),
           ".rs": ("rust", "tree_sitter_rust", "language"),
           ".js": ("javascript", "tree_sitter_javascript", "language"),
           ".jsx": ("jsx", "tree_sitter_javascript", "language"),
           ".ts": ("typescript", "tree_sitter_typescript", "language_typescript"),
           ".tsx": ("tsx", "tree_sitter_typescript", "language_tsx"),
           ".jl": ("julia", "tree_sitter_julia", "language"),
           ".kt": ("kotlin", "tree_sitter_kotlin", "language"),
           ".zig": ("zig", "tree_sitter_zig", "language"),
           ".sol": ("solidity", "tree_sitter_solidity", "language")}
_SRC_ONLY = {".cob": "cobol", ".cbl": "cobol", ".cobol": "cobol",
             ".f90": "fortran", ".f95": "fortran", ".f03": "fortran",
             ".f08": "fortran"}
_SKIP_DIRS = {"__pycache__", ".git", "node_modules", "target", "build",
              "dist", ".vendor", ".semgrep-final", "site-packages"}


def _load_tree(path: pathlib.Path):
    low = path.suffix.lower()
    if low in _SRC_ONLY:  # legacy: text-level analysis only
        return _SRC_ONLY[low], path.read_text(), None
    hit = _TSMODS.get(low)
    if hit is None:
        return None, None, None
    lang, modname, attr = hit
    mod = __import__(modname)
    from tree_sitter import Language, Parser
    from pegrex.tree_sitter_bridge import ts_to_pegrex
    src = path.read_text()
    root = Parser(Language(getattr(mod, attr)())).parse(src.encode())
    return lang, src, ts_to_pegrex(root.root_node, src)


def _plugins(paths: list[str] | None) -> dict:
    """Load user @analyzer/@opus callables from plain .* files."""
    found: dict[str, Callable] = {}
    for p in paths or []:
        spec = importlib.util.spec_from_file_location("mkspec_plugin_" +
                                                      pathlib.Path(p).stem, p)
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        exports = getattr(mod, "__mkspec_exports__", [])
        found.update({k: getattr(mod, k) for k in exports
                      if callable(getattr(mod, k, None))})
    return found


def _single_file_run(p, names=None, extra=None):
    """One source file -> (ctx, findings). The historical single-file path,
    byte-for-byte unchanged in behavior."""
    lang, src, tree = _load_tree(p)
    ctx = AnalysisContext(p, lang, src, tree)
    registry = {**ANALYZERS, **(_plugins(extra) if extra else {})}
    facts: list[Finding] = []
    for name, fn in registry.items():
        if names and name not in names:
            continue
        try:
            facts += [dataclasses.replace(f, analyzer=name)
                      for f in (fn(ctx) or [])]
        except Exception as exc:   # an analyzer must never kill the run
            facts.append(Finding(name, "analyzer-error", "INFO", 0, repr(exc)[:120]))
    return ctx, facts


_ZERO_SUMMARY = __import__("re").compile(r"^0 \w")


def run_analyzers(path, names=None, extra=None) -> tuple[AnalysisContext, list[Finding]]:
    """File -> the historical single-file run. Directory -> recursive mode:
    every analyzable .py file is analyzed independently, findings carry
    their relative path, opuses merge with per-file task prefixes, and
    opuses reporting zero items emit NO tasks (no work about nothing)."""
    p = pathlib.Path(path)
    if not p.is_dir():
        return _single_file_run(p, names, extra)
    def _wanted(f: pathlib.Path) -> bool:
        if not f.is_file():
            return False
        low = f.suffix.lower()
        if low not in _TSMODS and low not in _SRC_ONLY:
            return False
        return not any(part in _SKIP_DIRS or part.startswith(".")
                       for part in f.relative_to(p).parts)
    src_files = sorted(f for f in p.rglob("*") if _wanted(f))
    if not src_files:
        raise SystemExit(f"mkspec: {p} contains no analyzable source files -- "
                         "refusing to analyze nothing")
    all_facts: list[Finding] = []
    per_file = []
    for f in src_files:
        rel = str(f.relative_to(p))
        ctx1, facts1 = _single_file_run(f, names, extra)
        for fd in facts1:
            ev = f"{rel}: {fd.evidence}" if fd.evidence else rel
            all_facts.append(dataclasses.replace(fd, evidence=ev))
        per_file.append((rel, ctx1, facts1))
    import collections as _c
    langs = _c.Counter(c1.lang or "unknown" for _r, c1, _f in per_file)
    summary = ", ".join(f"{k} {v}" for k, v in langs.most_common())
    ctx = AnalysisContext(p, f"multi ({summary})", None, None)
    ctx._per_file = per_file  # consumed by run_opus (merge mode)
    ctx.lang_counts = dict(langs)
    return ctx, all_facts


def run_opus(ctx, facts, names=None, extra=None) -> dict:
    """Opus views over findings. Single-file ctx: historical behavior.
    Directory ctx (has _per_file): run each file independently and merge --
    summaries concatenated per file, tasks prefixed with [relpath], zero-item
    opuses emit no tasks."""
    per_file = getattr(ctx, "_per_file", None)
    if per_file is not None:
        merged: dict = {}
        for rel, ctx1, facts1 in per_file:
            res = run_opus(ctx1, facts1, names=names, extra=extra)
            for view, r in res.items():
                slot = merged.setdefault(view, {"summary": [], "tasks": []})
                slot["summary"].append(f"{rel}: {r.get('summary', '')}")
                if _ZERO_SUMMARY.match(r.get("summary", "")):
                    continue  # zero items -> no tasks
                for t in r.get("tasks", []):
                    slot["tasks"].append(dict(t, title=f"[{rel}] " + t.get("title", ""),
                                              **{"lines": t.get("lines", [])}))
        return {v: {"summary": "; ".join(s["summary"]), "tasks": s["tasks"]}
                for v, s in merged.items()}
    registry = {**OPUS, **(_plugins(extra) if extra else {})}
    return {n: fn(ctx, facts) for n, fn in registry.items()
            if not names or n in names}

def render_spec(ctx, facts, view_results, template, name) -> dict:
    from .templates import TEMPLATES
    if template in TEMPLATES:
        stub = TEMPLATES[template]
    elif template.endswith((".yaml", ".yml")):  # PyYAML templates, if installed
        import yaml
        stub = yaml.safe_load(pathlib.Path(template).read_text())
    else:
        stub = json.loads(pathlib.Path(template).read_text())
    spec = json.loads(json.dumps(stub))
    sha = hashlib.sha256(ctx.src.encode()).hexdigest()[:12] if ctx.src else "-"
    spec["meta"] |= {
        "name": name, "generated_by": "mkspec",
        "created_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "source_sha256": sha,
        "language": ctx.lang or ctx.path.suffix.lstrip("."),
        "analyzers": sorted({f.analyzer for f in facts}),
        "opus": sorted(view_results),
        "finding_count": len(facts),
    }
    per_file = getattr(ctx, "_per_file", None)
    if per_file is not None:
        files = [rel for rel, _c, _f in per_file]
        spec["preprocess"]["source_files"] = files[:200] + (
            [f"... {len(files) - 200} more"] if len(files) > 200 else [])
    else:
        spec["preprocess"]["source_files"] = [str(ctx.path)]
    spec["preprocess"]["context"] = (f"{len(facts)} findings across "
                                     f"{len({f.analyzer for f in facts})} analyzers")
    # trimmed: full finding dumps are stateless repetition of task content.
    # Keep counts + severities; details live in tasks[] where they actionable.
    import collections as _c
    counts = {}
    for f in facts:
        e = counts.setdefault(f.analyzer, {"total": 0, "by_severity": _c.Counter()})
        e["total"] += 1
        e["by_severity"][f.severity] += 1
    spec["analysis"]["finding_counts"] = {
        a: {"total": e["total"],
            "by_severity": dict(e["by_severity"])}
        for a, e in counts.items()}
    for v, res in view_results.items():
        spec["analysis"]["opus"][v] = {
            "task_count": len(res.get("tasks", [])),
            "summary": res.get("summary", "")}
    spec["analysis"] = {k: v for k, v in spec["analysis"].items() if v}

    prio = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}
    sev = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    tasks = sorted((dict(t, view=v) for v in view_results
                    for t in view_results[v].get("tasks", [])),
                   key=lambda t: (prio.get(t.get("priority", "P3"), 9),
                                  sev.get(t.get("severity", "INFO"), 9)))
    for i, t in enumerate(tasks, 1):
        t["id"] = f"T{i:02d}"
    # arch.index.json artifact (micsh/arch pattern): containers/modules/owns
    fns = [f for f in facts if f.analyzer == "structure"]
    modules = [{"file": str(ctx.path), "id": f.symbol or f.check_id,
                "boundary": f.evidence[:80],
                "owns": sorted({f2.check_id for f2 in facts
                                if f2.analyzer == f.analyzer
                                and f2.line == f.line})}
               for f in fns[:20] if f.check_id == "function"]
    spec["analysis"]["arch_index"] = {
        "containers": [{"id": ctx.path.stem, "path": str(ctx.path),
                        "description": spec["preprocess"].get("context", ""),
                        "modules": modules}]}
    spec["tasks"] = tasks
    from pegrex.contract import validate_contract, manifest_contract
    spec["contract_check"] = [
        str(e) for e in validate_contract(
            {"bundle": {"id": name, "version": spec["meta"].get("schema_version", "1.0.0"),
                        "effect": "read-write"},
             "requires": {"engine_version": "1.0.0"},
             "provides": {"commands": [{"name": t["id"], "description": t["title"][:80]}
                                       for t in tasks]}},
            [manifest_contract])]
    return spec


# ═══ CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="mkspec",
                                 description="Multi-view AI spec generator.")
    ap.add_argument("source"); ap.add_argument("name")
    ap.add_argument("--out", default="specs")
    ap.add_argument("--template", default="full",
                    help="TEMPLATES key or path to a JSON stub")
    ap.add_argument("--opus"); ap.add_argument("--analyzers")
    ap.add_argument("--extra", nargs="*", help="plugin .py files")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args(argv)
    if a.list:
        print("analyzers:", *sorted(ANALYZERS), sep="\n  ")
        print("opus:     ", *sorted(OPUS), sep="\n  ")
        return 0
    ctx, facts = run_analyzers(a.source,
                               a.analyzers.split(",") if a.analyzers else None,
                               a.extra)
    results = run_opus(ctx, facts,
                         a.opus.split(",") if a.opus else None, a.extra)
    spec = render_spec(ctx, facts, results, a.template, a.name)
    try:  # structural self-check
        import jsonschema
        jsonschema.validate(spec, {"type": "object", "required":
                                   ["meta", "preprocess", "analysis", "tasks",
                                    "postprocess"]})
    except ImportError:
        pass
    out = pathlib.Path(a.out); out.mkdir(parents=True, exist_ok=True)
    (out / f"{a.name}.spec.json").write_text(json.dumps(spec, indent=1))
    print(f"wrote {out / (a.name + '.spec.json')}  "
          f"({len(spec['tasks'])} tasks, {spec['meta']['finding_count']} findings)")
    return 0


from .analyzers import builtin as _ab
from .opus import builtin as _ob

if __name__ == "__main__":
    raise SystemExit(main())
