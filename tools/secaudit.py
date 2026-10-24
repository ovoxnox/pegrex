#!/usr/bin/env python3
"""
secaudit: Semgrep-derived pattern scan + intra-procedural taint, one engine.

Usage:
    python tools/secaudit.py <file.(py|go|rs|c)> [--lang LANG] [--json]

Exit code is always 0; the verdict lives in the findings list.
Extend the rule packs by editing the JSON catalogs — rules are data.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Iterable, Protocol

ROOT: pathlib.Path = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pegrex  # noqa: F401  (vendors .vendor/py bindings)

SEV_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
LANG_BY_EXT: dict[str, str] = {
    ".py": "python", ".go": "go", ".rs": "rust", ".c": "c", ".h": "c",
    ".cpp": "c", ".js": "javascript", ".jsx": "javascript", ".ts": "javascript",
    ".tsx": "typescript", ".ts": "typescript",
    ".sol": "solidity", ".vy": "solidity",
    ".jl": "julia", ".kt": "kotlin",
}


# ── Rule model 
@dataclass(frozen=True)
class Rule:
    """One converted semgrep rule. `match` is the entire executable logic."""
    id: str
    langs: tuple[str, ...]
    severity: str
    message: str
    kind: str            # "call" (AST-span scan) | "file" (whole-source regex)
    text: str
    node_type: str = "call"
    confidence: str = "medium"


class Catalog(Protocol):
    def rules(self, lang: str | None) -> Iterable[Rule]: ...


_REDOS = re.compile(r"\([^()]*[+*][^()]*\)[+*]|\([^)]*\|[^)]*\)[+*]\+")


def _redos_safe(rx: str) -> bool:
    """Reject patterns with nested unbounded quantifiers (catastrophic
    backtracking) and absurd lengths."""
    if len(rx) > 500:
        return False
    return _REDOS.search(rx) is None


class JsonCatalog:
    """Open/Closed: new packs are new JSON files, zero code changes.
    Hot-reloading: mtime-checked, so editing rules is live-testable."""

    def __init__(self, *paths: pathlib.Path, hot: bool = True) -> None:
        self._paths = [p for p in paths if p.exists()]
        self._hot = hot
        self._rules: list[Rule] = []
        self._mtimes: list[float] = []
        self._reload()

    def _reload(self) -> None:
        self._rules = []
        self._mtimes = []
        for p in self._paths:
            self._mtimes.append(p.stat().st_mtime)
            for raw in json.loads(p.read_text()).get("rules", []):
                m = raw["match"]
                if m["kind"] == "call" and not _redos_safe(m["text"]):
                    continue          # skip catastrophic patterns silently
                self._rules.append(Rule(
                    id=raw["id"], langs=tuple(raw.get("langs", ())),
                    severity=raw["severity"], message=raw.get("message", ""),
                    kind=m["kind"], text=m["text"],
                    node_type=m.get("node_type", "call"),
                    confidence=m.get("confidence", "medium")))

    def _stale(self) -> bool:
        return any(p.stat().st_mtime != m
                   for p, m in zip(self._paths, self._mtimes))

    def rules(self, lang: str | None) -> Iterable[Rule]:
        if self._hot and self._stale():
            self._reload()
        # typescript is a superset of javascript: JS rules apply to TS too
        langs_wanted = {lang, "javascript"} if lang == "typescript" else {lang}
        for r in self._rules:
            if r.kind == "call" and (not r.langs or set(r.langs) & langs_wanted):
                yield r
            elif r.kind == "file" and (not r.langs or not lang
                                       or set(r.langs) & langs_wanted
                                       or "regex" in r.langs):
                yield r


# ── AST providers (Dependency Inversion)
class AstProvider(Protocol):
    lang: str | None
    src: str
    tree: object | None


class TreeSitterAst:
    """Parses via real tree-sitter; falls back to regex-only mode."""

    def __init__(self, path: pathlib.Path) -> None:
        self.lang: str | None = LANG_BY_EXT.get(path.suffix)
        self.src: str = path.read_text()
        self.tree: object | None = None
        if self.lang in ("python", "go", "rust", "javascript", "solidity", "julia", "kotlin"):
            mod = __import__({"javascript": "tree_sitter_javascript"}.get(self.lang, f"tree_sitter_{self.lang}"))
            from tree_sitter import Language, Parser
            root = Parser(Language(mod.language())).parse(self.src.encode())
            from pegrex.tree_sitter_bridge import ts_to_pegrex
            self.tree = ts_to_pegrex(root.root_node, self.src)


@dataclass
class Finding:
    id: str
    severity: str
    confidence: str
    line: int
    evidence: str
    message: str = ""
    kind: str = "pattern"
    function: str | None = None


# ── Scanners
def _callee_hints(rx: str) -> list:
    """Every literal token in the rule regex (alternants included) for
    prefiltering.  A rule is skipped only when NONE of its tokens appear
    in the source -- never drop on a partial match."""
    return re.findall(r"[A-Za-z_]\w{2,}", rx)

def _callee_hint(rx: str):
    """A cheap literal substring from the rule regex for prefiltering."""
    m = re.search(r"\(\?:\)?([A-Za-z_]\w{2,})", rx)
    return m.group(1) if m else None


class PatternScanner:
    """call rules: scan normalized AST spans with the rule regex."""

    def __init__(self, catalog: Catalog) -> None:
        self.catalog = catalog

    def scan(self, ast: AstProvider) -> list[Finding]:
        if ast.tree is None or ast.lang is None:
            return []
        from pegrex.patterns import Pattern, scan
        rules = [r for r in self.catalog.rules(ast.lang) if r.kind == "call"]
        # substring prefilter: skip regex work when no callee token appears
        if ast.tree is not None:
            src_l = ast.src
            rules = [r for r in rules
                 if any(t in src_l for t in _callee_hints(r.text))]
        pats = []
        for r in rules:
            aliases = {"call": ("call", "call_expression")}.get(
                r.node_type, (r.node_type,))
            for alias in aliases:
                pats.append(Pattern(node_type=alias, text=r.text, id=r.id))
        by_id = {r.id: r for r in rules}
        out = []
        for node, pat, _ in scan(ast.tree, pats, ast.src):
            r = by_id[pat.id]
            out.append(Finding(r.id, r.severity, r.confidence,
                               ast.src[:node.pos].count("\n") + 1,
                               ast.src[node.pos:node.endpos].strip()[:90],
                               message=r.message))
        return out


class RegexScanner:
    """file rules: whole-source regex; language-agnostic."""

    def scan(self, ast: AstProvider, catalog: Catalog) -> list[Finding]:
        out = []
        for r in catalog.rules(ast.lang):
            if r.kind != "file" or len(r.text) < 10:
                continue
            try:
                rx = re.compile(r.text)
            except re.error:
                continue
            for m in rx.finditer(ast.src):
                out.append(Finding(r.id, r.severity, r.confidence,
                                   ast.src[:m.start()].count("\n") + 1,
                                   m.group(0)[:90], message=r.message))
        return out


class TaintScanner:
    """taint rules: sources -> sinks with sanitizer suppression."""

    def scan(self, ast: AstProvider, taint_rules: list[dict]) -> list[Finding]:
        if ast.tree is None or ast.lang is None:
            return []
        from pegrex.taint import analyze_taint
        out = []
        for r in taint_rules:
            if r["langs"] and ast.lang not in r["langs"]:
                continue
            result = analyze_taint(ast.tree, ast.src, r)
            findings_t = result[0] if isinstance(result, tuple) else result
            for f in findings_t:
                out.append(Finding(r["id"], r["severity"], "high", f["line"],
                                   f["evidence"], message=r["message"],
                                   kind="taint", function=f.get("function")))
        return out


# ── Orchestrator
@dataclass
class Auditor:
    """Facade: one entry point, three strategies, dedup + ordering."""
    catalog: Catalog = field(init=False)
    taint_rules: list[dict] = field(init=False)

    def __post_init__(self) -> None:
        self.catalog = JsonCatalog(ROOT / "pegrex/secrules.json")
        tp = ROOT / "pegrex/secrules_taint.json"
        self.taint_rules = (json.loads(tp.read_text())["rules"]
                            if tp.exists() else [])
        self._patterns = PatternScanner(self.catalog)

    def audit(self, path: str, lang: str | None = None) -> list[Finding]:
        ast = TreeSitterAst(pathlib.Path(path))
        if lang:
            ast.lang = lang
        if ast.lang == "typescript":
            import types as _types
            src_text, ts_tree = _ts_parse(path)
            ast = _types.SimpleNamespace(lang="typescript",
                                         src=src_text, tree=ts_tree)
        findings = (self._patterns.scan(ast)
                    + RegexScanner().scan(ast, self.catalog)
                    + TaintScanner().scan(ast, self.taint_rules))
        seen, uniq = set(), []
        for f in findings:
            key = (f.id, f.line)
            if key not in seen:
                seen.add(key)
                uniq.append(f)
        uniq.sort(key=lambda f: (SEV_ORDER.get(f.severity, 9), f.line))
        return uniq


def _semgrep_findings(semgrep_bin: str, path: str) -> list[dict]:
    """Passthrough to the official engine for rules our catalog can't cover."""
    r = subprocess.run([semgrep_bin, "--config", "auto", "--json", "--quiet", path],
                       capture_output=True, text=True, timeout=600)
    out = []
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return out
    for hit in data.get("results", []):
        out.append({"id": hit["check_id"], "severity": "MEDIUM",
                    "confidence": "external",
                    "line": hit["start"]["line"],
                    "evidence": hit["extra"].get("lines", "").strip()[:90],
                    "message": hit["extra"].get("message", "")[:140],
                    "kind": "semgrep"})
    return out


def _ts_parse(path):
    import pipeline
    import pathlib as _pl
    p = _pl.Path(path)
    src = p.read_text()
    parse, _, _ = pipeline.typescript_frontend()
    from pegrex.tree_sitter_bridge import ts_to_pegrex as _t2p
    try:
        body = parse(src)
    except Exception:
        return src, None
    return src, body


def audit(path: str, lang: str | None = None) -> list[dict]:
    """Library entry: findings as plain dicts (stable for JSON round-trips)."""
    return [f.__dict__ for f in Auditor().audit(path, lang)]


def main() -> int:
    ap = argparse.ArgumentParser(prog="secaudit")
    ap.add_argument("file")
    ap.add_argument("--lang", default=None)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    findings = audit(a.file, a.lang)
    if a.json:
        print(json.dumps({"file": a.file, "findings": findings,
                          "total": len(findings)}, indent=1))
    else:
        for f in findings:
            print(f"{f['severity']:9} {f['confidence']:7} {f['id']:44} "
                  f"L{f['line']:<4} {f.get('kind', ''):8} {f['evidence']}")
        print(f"\ntotal: {len(findings)} findings")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
