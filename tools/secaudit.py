#!/usr/bin/env python3
"""
secaudit: Semgrep-derived pattern scan + intra-procedural taint, one engine.

Usage:
    python tools/secaudit.py <file.(py|go|rs|c)> [--lang LANG] [--json]

Exit code is 0 in report-only mode. Use --fail-on SEVERITY and
--fail-on-unknown for CI gates. Extend rule packs by editing JSON catalogs.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import multiprocessing as mp
import pathlib
import queue
import re
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Iterable, Protocol

ROOT: pathlib.Path = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pegrex  # noqa: F401  (vendors .vendor/py bindings)

SEV_ORDER: dict[str, int] = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
MAX_SOURCE_BYTES = 2_000_000
MAX_MATCHES_PER_RULE = 1000
REGEX_TIMEOUT_MS = 2000
from pegrex.languages import (detect_language, get_language, normalize_language,
                              parse_source as parse_registered_source,
                              parser_provenance, rule_languages,
                              security_rule_packs)
from pegrex.rules import canonical_semantics, merge_rule_packs, read_rule_pack


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
    semantics: str = ""
    provenance: dict = field(default_factory=dict)
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    references: tuple[str, ...] = ()

    @property
    def execution_id(self) -> str:
        """Distinct internal identity for same-ID rules with distinct semantics."""
        return f"{self.id}@{self.semantics[:16]}" if self.semantics else self.id


def _string_tuple(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    return tuple(str(item) for item in value)


def _security_metadata(raw: dict) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Read explicit CWE/OWASP metadata; infer only unambiguous common classes."""
    metadata = raw.get("metadata") or {}
    cwe = _string_tuple(raw.get("cwe", metadata.get("cwe")))
    owasp = _string_tuple(raw.get("owasp", metadata.get("owasp")))
    references = _string_tuple(raw.get("references", metadata.get("references")))
    text = (raw.get("id", "") + " " + raw.get("message", "")).lower()
    inferred = (
        (("sql", "sqli"), "CWE-89", "A03:2021 Injection"),
        (("eval", "exec", "code-injection"), "CWE-94", "A03:2021 Injection"),
        (("command-injection", "shell-injection", "os-command"), "CWE-78", "A03:2021 Injection"),
        (("xss", "cross-site-scripting"), "CWE-79", "A03:2021 Injection"),
        (("path-traversal", "directory-traversal"), "CWE-22", "A01:2021 Broken Access Control"),
        (("ssrf",), "CWE-918", "A10:2021 Server-Side Request Forgery"),
        (("unsafe-deserialization", "pickle", "yaml-load"), "CWE-502", "A08:2021 Software and Data Integrity Failures"),
        (("hardcoded-password", "hardcoded-secret", "hardcoded-credential"), "CWE-798", "A07:2021 Identification and Authentication Failures"),
        (("weak-hash", "md5", "sha1", "insecure-cipher"), "CWE-327", "A02:2021 Cryptographic Failures"),
        (("insecure-random", "weak-random"), "CWE-330", "A02:2021 Cryptographic Failures"),
        (("cleartext", "http-request", "disabled-tls", "insecure-transport"), "CWE-319", "A02:2021 Cryptographic Failures"),
    )
    if not cwe:
        def mentioned(needle):
            return re.search(r"(?<![a-z0-9])" + re.escape(needle)
                             + r"(?![a-z0-9])", text) is not None
        for needles, cwe_id, category in inferred:
            if any(mentioned(needle) for needle in needles):
                cwe, owasp = (cwe_id,), owasp or (category,)
                break
    return cwe, owasp, references


class Catalog(Protocol):
    def rules(self, lang: str | None) -> Iterable[Rule]: ...


_REDOS = re.compile(r"\([^()]*[+*][^()]*\)[+*]|\([^)]*\|[^)]*\)[+*]\+")
_QUANTIFIED_GROUP = re.compile(
    r"\((?:[^()\\]|\\.)*(?:[+*]|\{\d*,\d*\})(?:[^()\\]|\\.)*\)(?:[+*]|\{\d*,\})")


def _redos_safe(rx: str) -> bool:
    """Reject nested unbounded quantifiers and absurd pattern lengths."""
    if len(rx) > 500:
        return False
    return _REDOS.search(rx) is None and _QUANTIFIED_GROUP.search(rx) is None


class JsonCatalog:
    """Open/Closed: new packs are new JSON files, zero code changes.
    Hot-reloading: mtime-checked, so editing rules is live-testable."""

    def __init__(self, *paths: pathlib.Path, hot: bool = True) -> None:
        self._paths = [p for p in paths if p.exists()]
        self._hot = hot
        self._rules: list[Rule] = []
        self._rejected: list[dict] = []
        self._mtimes: list[float] = []
        self._pack = merge_rule_packs([])
        self._reload()

    def _reload(self) -> None:
        self._rules = []
        self._rejected = []
        self._mtimes = [p.stat().st_mtime for p in self._paths]
        self._pack = merge_rule_packs(read_rule_pack(path) for path in self._paths)
        for record in self._pack.records:
            raw = record.rule
            m = raw["match"]
            reason = None
            if not _redos_safe(m["text"]):
                reason = "unsafe or oversized regular expression"
            else:
                try:
                    re.compile(m["text"])
                except re.error as exc:
                    reason = f"invalid regular expression: {exc}"
            if reason:
                self._rejected.append({"id": raw["id"],
                                       "langs": raw.get("langs", []),
                                       "kind": m["kind"], "reason": reason})
                continue
            cwe, owasp, references = _security_metadata(raw)
            self._rules.append(Rule(
                id=raw["id"], langs=tuple(raw.get("langs", ())),
                severity=raw["severity"], message=raw.get("message", ""),
                kind=m["kind"], text=m["text"],
                node_type=m.get("node_type", "call"),
                confidence=m.get("confidence", "medium"),
                semantics=record.semantics, provenance=record.origin.to_dict(),
                cwe=cwe, owasp=owasp, references=references))

    def _stale(self) -> bool:
        return any(p.stat().st_mtime != m
                   for p, m in zip(self._paths, self._mtimes))

    def rules(self, lang: str | None) -> Iterable[Rule]:
        if self._hot and self._stale():
            self._reload()
        # Cross-language rule reuse is explicitly declared by the registry.
        langs_wanted = set(rule_languages(lang)) if lang else set()
        for r in self._rules:
            if r.kind == "call" and (not r.langs or set(r.langs) & langs_wanted):
                yield r
            elif r.kind == "file" and (not r.langs or not lang
                                       or set(r.langs) & langs_wanted
                                       or "regex" in r.langs):
                yield r

    def all_rules(self) -> Iterable[Rule]:
        """All valid rules for unknown-language coverage explanations."""
        if self._hot and self._stale():
            self._reload()
        return iter(self._rules)

    def rejected(self, lang: str | None) -> list[dict]:
        """Rules not executed, exposed as scanner coverage uncertainty."""
        if self._hot and self._stale():
            self._reload()
        wanted = set(rule_languages(lang)) if lang else set()
        return [r for r in self._rejected
                if not r["langs"] or not lang or set(r["langs"]) & wanted
                or "regex" in r["langs"]]

    def coverage(self, lang: str | None) -> dict:
        if self._hot and self._stale():
            self._reload()
        report = self._pack.coverage(lang, rule_languages=rule_languages(lang) if lang else ())
        report["rejected"] = self.rejected(lang)
        return report


# ── AST providers (Dependency Inversion)
class AstProvider(Protocol):
    lang: str | None
    src: str
    tree: object | None


class TreeSitterAst:
    """Parses via real tree-sitter; falls back to regex-only mode."""

    def __init__(self, path: pathlib.Path, max_bytes: int = MAX_SOURCE_BYTES,
                 lang: str | None = None) -> None:
        self.lang: str | None = detect_language(path, lang)
        self.tree: object | None = None
        self.parse_error: str | None = None
        self.input_error: str | None = None
        self.parser_used: str | None = None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            data = handle.read(max_bytes + 1)
            digest.update(data)
            self.source_bytes = len(data)
            if len(data) > max_bytes:
                while chunk := handle.read(1024 * 1024):
                    digest.update(chunk)
                    self.source_bytes += len(chunk)
        self.source_digest = digest.hexdigest()
        if len(data) > max_bytes:
            self.src = ""
            self.input_error = f"input exceeds {max_bytes} byte limit; scan refused"
            return
        self.src = data.decode("utf-8")
        if self.lang and "audit" in get_language(self.lang).capabilities:
            try:
                self.tree = parse_registered_source(self.lang, self.src)
                self.parser_used = get_language(self.lang).parse_adapter
            except (ImportError, NotImplementedError, ValueError, RuntimeError) as exc:
                self.parse_error = f"{type(exc).__name__}: {str(exc)[:200]}"

    @classmethod
    def from_source(cls, source: str, lang: str, *, tree=None,
                    max_bytes: int = MAX_SOURCE_BYTES) -> "TreeSitterAst":
        """Build a provider over an existing source/tree without file I/O or reparsing."""
        obj = cls.__new__(cls)
        obj.lang = normalize_language(lang)
        obj.tree = tree
        obj.parse_error = None
        obj.input_error = None
        obj.parser_used = None
        obj.src = source
        encoded = source.encode("utf-8")
        obj.source_digest = hashlib.sha256(encoded).hexdigest()
        obj.source_bytes = len(encoded)
        if len(encoded) > max_bytes:
            obj.src = ""
            obj.tree = None
            obj.input_error = f"input exceeds {max_bytes} byte limit; scan refused"
            return obj
        if obj.lang is None:
            raise ValueError(f"unsupported audit language {lang!r}")
        if obj.tree is None and "audit" in get_language(obj.lang).capabilities:
            try:
                obj.tree = parse_registered_source(obj.lang, obj.src)
                obj.parser_used = get_language(obj.lang).parse_adapter
            except (ImportError, NotImplementedError, ValueError, RuntimeError) as exc:
                obj.parse_error = f"{type(exc).__name__}: {str(exc)[:200]}"
        elif obj.tree is not None:
            obj.parser_used = get_language(obj.lang).parse_adapter
        return obj


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
    column: int = 1
    end_line: int | None = None
    end_column: int | None = None
    file: str | None = None
    rule_key: str | None = None
    cwe: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    rule_provenance: dict = field(default_factory=dict)
    source: str | None = None
    sink: str | None = None
    sources: list[dict] = field(default_factory=list)
    suppressed: bool = False
    suppression: dict | None = None
    suppression_error: str | None = None


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
                pats.append(Pattern(node_type=alias, text=r.text, id=r.execution_id))
        by_id = {r.execution_id: r for r in rules}
        out = []
        for node, pat, _ in scan(ast.tree, pats, ast.src):
            r = by_id[pat.id]
            evidence = ast.src[node.pos:node.endpos].strip()[:90]
            line = ast.src[:node.pos].count("\n") + 1
            column = node.pos - ast.src.rfind("\n", 0, node.pos)
            end_line = ast.src[:node.endpos].count("\n") + 1
            end_column = node.endpos - ast.src.rfind("\n", 0, node.endpos)
            out.append(Finding(
                r.id, r.severity, r.confidence, line, evidence,
                message=r.message, column=column, end_line=end_line,
                end_column=end_column, rule_key=r.execution_id, cwe=r.cwe,
                owasp=r.owasp, references=r.references,
                rule_provenance=r.provenance, sink=evidence))
        return out


def _regex_worker(rules, src, output):
    """Isolated regex execution: the parent can terminate catastrophic matches."""
    findings, errors = [], []
    try:
        for rule in rules:
            try:
                rx = re.compile(rule.text)
            except re.error as exc:
                errors.append(f"{rule.id}: {exc}")
                continue
            for index, match in enumerate(rx.finditer(src)):
                if index >= MAX_MATCHES_PER_RULE:
                    errors.append(f"{rule.id}: match cap {MAX_MATCHES_PER_RULE} exceeded")
                    break
                evidence = match.group(0)[:90]
                findings.append(Finding(
                    rule.id, rule.severity, rule.confidence,
                    src[:match.start()].count("\n") + 1,
                    evidence, message=rule.message,
                    column=match.start() - src.rfind("\n", 0, match.start()),
                    end_line=src[:match.end()].count("\n") + 1,
                    end_column=match.end() - src.rfind("\n", 0, match.end()),
                    rule_key=rule.execution_id, cwe=rule.cwe, owasp=rule.owasp,
                    references=rule.references, rule_provenance=rule.provenance,
                    sink=evidence))
    except Exception as exc:  # worker failure becomes explicit unknown
        errors.append(f"{type(exc).__name__}: {str(exc)[:160]}")
    output.put((findings, errors))


class RegexScanner:
    """Whole-source regexes with an enforceable process-level deadline."""

    def scan(self, ast: AstProvider, catalog: Catalog,
             timeout_ms: int = REGEX_TIMEOUT_MS) -> list[Finding]:
        rules = [r for r in catalog.rules(ast.lang)
                 if r.kind == "file" and len(r.text) >= 10]
        if not rules or not ast.src:
            return []
        ctx = mp.get_context("spawn")
        output = ctx.Queue()
        process = ctx.Process(target=_regex_worker, args=(rules, ast.src, output),
                              daemon=True)
        process.start()
        process.join(timeout_ms / 1000)
        if process.is_alive():
            process.terminate()
            process.join(1)
            if process.is_alive() and hasattr(process, "kill"):
                process.kill()
                process.join()
            return [Finding("PEGREX-REGEX-UNKNOWN", "MEDIUM", "low", 1, "",
                            message=f"regex scan exceeded {timeout_ms}ms; coverage incomplete",
                            kind="unknown")]
        try:
            findings, errors = output.get(timeout=0.2)
        except queue.Empty:
            return [Finding("PEGREX-REGEX-UNKNOWN", "MEDIUM", "low", 1, "",
                            message="regex worker returned no result", kind="unknown")]
        finally:
            output.close()
        if errors:
            findings.append(Finding(
                "PEGREX-REGEX-UNKNOWN", "MEDIUM", "low", 1, "",
                message="; ".join(errors)[:400], kind="unknown"))
        return findings


class TaintScanner:
    """taint rules: sources -> sinks with sanitizer suppression."""

    def scan(self, ast: AstProvider, taint_rules: list[dict]) -> list[Finding]:
        if ast.tree is None or ast.lang is None:
            return []
        if "taint" not in get_language(ast.lang).capabilities:
            return []
        from pegrex.taint import analyze_taint
        out = []
        id_counts = {}
        for rule in taint_rules:
            id_counts[rule["id"]] = id_counts.get(rule["id"], 0) + 1
        for r in taint_rules:
            if r["langs"] and not (set(r["langs"]) & rule_languages(ast.lang)):
                continue
            result = analyze_taint(ast.tree, ast.src, r)
            findings_t, unknowns = result if isinstance(result, tuple) else (result, [])
            cwe, owasp, references = _security_metadata(r)
            rule_key = (r["id"] if id_counts[r["id"]] == 1 else
                        f"{r['id']}@{canonical_semantics(r)[:16]}")
            for f in findings_t:
                out.append(Finding(
                    r["id"], r["severity"], "high", f["line"], f["evidence"],
                    message=r["message"], kind="taint", function=f.get("function"),
                    column=f.get("column", 1), rule_key=rule_key,
                    cwe=cwe, owasp=owasp, references=references,
                    source=f.get("source"), sink=f.get("sink", f["evidence"]),
                    sources=f.get("sources", [])))
            for f in unknowns:
                out.append(Finding(
                    r["id"], r["severity"], "low", f["line"], f["evidence"],
                    message="UNKNOWN taint flow: " + r["message"],
                    kind="unknown", function=f.get("function"),
                    column=f.get("column", 1), rule_key=rule_key,
                    cwe=cwe, owasp=owasp, references=references,
                    source=f.get("source"), sink=f.get("sink", f["evidence"]),
                    sources=f.get("sources", [])))
        return out


_SUPPRESSION = re.compile(r"pegrex:ignore\s+([^\s:]+)(.*)", re.IGNORECASE)


def _apply_suppressions(findings: list[Finding], source: str) -> None:
    """Apply justified in-source suppressions without hiding active findings.

    Syntax: ``# pegrex:ignore RULE-ID -- reviewer rationale`` on the finding's
    line or the immediately preceding line. A missing rationale is not a valid
    suppression and remains visible on the finding.
    """
    directives = []
    for line_no, line in enumerate(source.splitlines(), 1):
        match = _SUPPRESSION.search(line)
        if not match or not ("#" in line[:match.start()] or "//" in line[:match.start()]):
            continue
        remainder = match.group(2).strip()
        separator = remainder.startswith("--") or remainder.startswith(":")
        justification = remainder[2:].strip() if separator else ""
        directives.append((line_no, match.group(1), justification, separator))
    for finding in findings:
        for line_no, rule_id, justification, separated in directives:
            if line_no not in (finding.line - 1, finding.line):
                continue
            if rule_id not in (finding.id, finding.rule_key):
                continue
            if separated and justification:
                finding.suppressed = True
                finding.suppression = {
                    "kind": "inSource", "status": "accepted",
                    "justification": justification, "line": line_no,
                }
            else:
                finding.suppression_error = "suppression requires '-- JUSTIFICATION'"
            break


# ── Orchestrator
@dataclass
class Auditor:
    """Facade: one entry point, three strategies, dedup + ordering."""
    catalog: Catalog = field(init=False)
    taint_rules: list[dict] = field(init=False)

    def __post_init__(self) -> None:
        pack_path = lambda name: ROOT / "pegrex" / name
        self.catalog = JsonCatalog(*(
            pack_path(name) for name in security_rule_packs(capability="audit")),
            hot=False)
        taint_paths = [pack_path(name)
                       for name in security_rule_packs(capability="taint")]
        self.taint_pack = merge_rule_packs(
            read_rule_pack(path) for path in taint_paths if path.exists())
        self.taint_rules = self.taint_pack.rules
        self._patterns = PatternScanner(self.catalog)

    def coverage(self, lang: str | None = None) -> dict:
        """Rule execution coverage, provenance, and intentional exclusions."""
        return {"pattern": self.catalog.coverage(lang),
                "taint": self.taint_pack.coverage(
                    lang, rule_languages=rule_languages(lang) if lang else ())}

    def _audit_ast(self, ast: AstProvider) -> list[Finding]:
        if ast.input_error:
            return [Finding("PEGREX-INPUT-UNKNOWN", "MEDIUM", "low", 1, "",
                            message=ast.input_error, kind="unknown")]
        findings = (self._patterns.scan(ast)
                    + RegexScanner().scan(ast, self.catalog)
                    + TaintScanner().scan(ast, self.taint_rules))
        if ast.lang is None:
            findings.append(Finding(
                "PEGREX-LANGUAGE-UNKNOWN", "MEDIUM", "low", 1, "",
                message="Source language is unsupported or could not be detected; AST and taint rules were skipped",
                kind="unknown"))
        if ast.lang and ast.tree is None:
            findings.append(Finding(
                "PEGREX-PARSER-UNKNOWN", "MEDIUM", "low", 1, "",
                message=(f"Parser unavailable for {ast.lang}; scanner coverage is incomplete"
                         + (f": {ast.parse_error}" if ast.parse_error else "")),
                kind="unknown"))
        rejected = self.catalog.rejected(ast.lang)
        if rejected:
            findings.append(Finding(
                "PEGREX-RULES-UNKNOWN", "MEDIUM", "low", 1, "",
                message=(f"{len(rejected)} rules not executed; coverage incomplete: "
                         + "; ".join(f"{r['id']} ({r['reason']})" for r in rejected[:5])),
                kind="unknown"))
        seen, uniq = set(), []
        for f in findings:
            key = (f.id, f.line, f.kind, f.evidence)
            if key not in seen:
                seen.add(key)
                uniq.append(f)
        uniq.sort(key=lambda f: (SEV_ORDER.get(f.severity, 9), f.line, f.id,
                                 f.rule_key or "", f.evidence))
        _apply_suppressions(uniq, ast.src)
        return uniq

    @staticmethod
    def _catalog_snapshot(coverage: dict) -> dict:
        return {key: coverage[key] for key in (
            "catalog_version", "active", "disabled", "duplicates_removed",
            "inapplicable", "provenance")}

    def file_coverage(self, ast: AstProvider, findings: list[Finding], *,
                      path: str | None = None) -> dict:
        """Explain file/language/rule execution and every intentional coverage gap."""
        coverage = self.coverage(ast.lang)
        unknowns = [f.message for f in findings if f.kind == "unknown"]
        languages = set(rule_languages(ast.lang)) if ast.lang else set()
        audit_supported = bool(ast.lang and "audit" in get_language(ast.lang).capabilities)
        taint_supported = bool(ast.lang and "taint" in get_language(ast.lang).capabilities)
        pattern_executed, pattern_skipped = [], []

        candidate_rules = (self.catalog.all_rules() if ast.lang is None
                           else self.catalog.rules(ast.lang))
        for rule in candidate_rules:
            row = {"id": rule.execution_id, "kind": rule.kind}
            reason = None
            if ast.input_error:
                reason = "input-refused"
            elif rule.kind == "call":
                if ast.lang is None:
                    reason = "language-unknown"
                elif not audit_supported:
                    reason = "audit-unsupported-for-language"
                elif ast.tree is None:
                    reason = "parser-unavailable"
                elif not any(token in ast.src for token in _callee_hints(rule.text)):
                    reason = "no-callee-hint-in-source"
            elif len(rule.text) < 10:
                reason = "short-regex-not-executed"
            elif not ast.src:
                reason = "empty-input"
            if reason is None:
                pattern_executed.append(row)
            else:
                pattern_skipped.append({**row, "reason": reason})
        for rule_id in coverage["pattern"]["disabled_rules"]:
            pattern_skipped.append({"id": rule_id, "kind": "pattern", "reason": "disabled"})
        for rule_id in coverage["pattern"]["inapplicable_rules"]:
            pattern_skipped.append({"id": rule_id, "kind": "pattern",
                                    "reason": "language-not-applicable"})
        for rejected in coverage["pattern"].get("rejected", []):
            pattern_skipped.append({"id": rejected["id"], "kind": rejected["kind"],
                                    "reason": "rule-rejected: " + rejected["reason"]})

        taint_executed, taint_skipped = [], []
        id_counts = {}
        for record in self.taint_pack.records:
            rule_id = record.rule["id"]
            id_counts[rule_id] = id_counts.get(rule_id, 0) + 1
        for record in self.taint_pack.records:
            rule = record.rule
            rule_id = (rule["id"] if id_counts[rule["id"]] == 1 else
                       f"{rule['id']}@{record.semantics[:16]}")
            row = {"id": rule_id, "kind": "taint"}
            applies = (ast.lang is None or not rule.get("langs") or
                       bool(set(rule.get("langs", ())) & languages))
            reason = None
            if not applies:
                reason = "language-not-applicable"
            elif ast.input_error:
                reason = "input-refused"
            elif ast.lang is None:
                reason = "language-unknown"
            elif not taint_supported:
                reason = "taint-unsupported-for-language"
            elif ast.tree is None:
                reason = "parser-unavailable"
            (taint_executed if reason is None else taint_skipped).append(
                row if reason is None else {**row, "reason": reason})
        for rule_id in coverage["taint"]["disabled_rules"]:
            taint_skipped.append({"id": rule_id, "kind": "taint", "reason": "disabled"})
        for rule_id in coverage["taint"]["inapplicable_rules"]:
            # Already present from the active-record pass only when a pack
            # reports a separate inapplicable record; avoid duplicate rows.
            row = {"id": rule_id, "kind": "taint", "reason": "language-not-applicable"}
            if row not in taint_skipped:
                taint_skipped.append(row)

        regex_undecided = any(f.id == "PEGREX-REGEX-UNKNOWN" for f in findings)
        undecided = ([dict(row) for row in pattern_executed if row["kind"] == "file"]
                     if regex_undecided else [])
        return {
            "schema": "pegrex.scan-coverage.v1",
            "status": "partial" if unknowns else "complete",
            "file": {"path": path, "sha256": ast.source_digest,
                     "bytes": ast.source_bytes,
                     "status": "refused" if ast.input_error else "scanned"},
            "language": {"id": ast.lang,
                         "status": "supported" if audit_supported else "unsupported",
                         "audit": audit_supported, "taint": taint_supported},
            "rules": {
                "pattern": {"executed": pattern_executed, "skipped": pattern_skipped,
                            "undecided": undecided},
                "taint": {"executed": taint_executed, "skipped": taint_skipped,
                          "undecided": []},
            },
            "unknowns": unknowns,
        }

    def provenance(self, ast: AstProvider, *, path: str | None = None,
                   osv: dict | None = None) -> dict:
        coverage = self.coverage(ast.lang)
        catalogs = {kind: self._catalog_snapshot(coverage[kind])
                    for kind in ("pattern", "taint")}
        identity = json.dumps({kind: data["catalog_version"]
                               for kind, data in catalogs.items()},
                              sort_keys=True, separators=(",", ":"))
        return {
            "schema": "pegrex.security-provenance.v1",
            "source": {"path": path, "sha256": ast.source_digest,
                       "bytes": ast.source_bytes},
            "language": ast.lang,
            "parser": (parser_provenance(ast.lang, used=ast.parser_used)
                       if ast.lang else {"status": "unknown-language"}),
            "rules": catalogs,
            "rule_catalog_version": "sha256:" + hashlib.sha256(identity.encode()).hexdigest(),
            "osv": osv or {"mode": "offline", "status": "not_applicable",
                           "snapshot": None},
            "configuration": {
                "max_source_bytes": MAX_SOURCE_BYTES,
                "max_matches_per_rule": MAX_MATCHES_PER_RULE,
                "regex_timeout_ms": REGEX_TIMEOUT_MS,
                "network": "disabled-for-source-audit",
            },
        }

    def _audit_with_ast(self, ast: AstProvider, path: str | None) -> list[Finding]:
        findings = self._audit_ast(ast)
        for finding in findings:
            finding.file = path
        return findings

    def audit(self, path: str, lang: str | None = None) -> list[Finding]:
        ast = TreeSitterAst(pathlib.Path(path), lang=lang)
        return self._audit_with_ast(ast, str(path))

    def scan_report(self, path: str, lang: str | None = None, *,
                    osv: dict | None = None) -> dict:
        """Reproducible, offline source scan with exact input/tool identity."""
        ast = TreeSitterAst(pathlib.Path(path), lang=lang)
        findings = self._audit_with_ast(ast, str(path))
        from pegrex.schema import finding_document, unknown_document
        rows = [finding_document(finding.__dict__) for finding in findings]
        unknowns = [unknown_document(finding.message, source=str(path), resource="scan-coverage")
                    for finding in findings if finding.kind == "unknown"]
        return {
            "schema": "pegrex.security-scan.v1",
            "file": str(path), "language": ast.lang,
            "findings": rows, "total": len(rows), "unknowns": unknowns,
            "active_total": sum(not f.suppressed for f in findings),
            "suppressed_total": sum(f.suppressed for f in findings),
            "coverage": self.file_coverage(ast, findings, path=str(path)),
            "provenance": self.provenance(ast, path=str(path), osv=osv),
        }

    def audit_source(self, source: str, lang: str, *, tree=None) -> list[Finding]:
        """Audit existing source and, when supplied, its already-normalized tree."""
        return self._audit_ast(TreeSitterAst.from_source(source, lang, tree=tree))


def _semgrep_findings(semgrep_bin: str, path: str, config: str) -> list[dict]:
    """Offline passthrough using an explicit local/versioned Semgrep config."""
    if not config or config == "auto":
        raise ValueError("semgrep scans require an explicit local/versioned config")
    r = subprocess.run([semgrep_bin, "--config", config, "--metrics", "off",
                        "--json", "--quiet", path], shell=False,
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
    from pegrex.languages import get_contract_frontend
    p = pathlib.Path(path)
    src = p.read_text(encoding="utf-8")
    parse, _, _ = get_contract_frontend("typescript")()
    try:
        body = parse(src)
    except Exception:
        return src, None
    return src, body


def audit(path: str, lang: str | None = None) -> list[dict]:
    """Library entry: findings as plain dicts (stable for JSON round-trips)."""
    return [f.__dict__ for f in Auditor().audit(path, lang)]


def audit_source(source: str, lang: str, *, tree=None) -> list[dict]:
    """Source/tree entry point used by shared analysis sessions and the LSP."""
    return [f.__dict__ for f in Auditor().audit_source(source, lang, tree=tree)]


def audit_report(path: str, lang: str | None = None, *,
                 osv: dict | None = None) -> dict:
    return Auditor().scan_report(path, lang, osv=osv)


def aggregate_scan_coverage(reports: list[dict]) -> dict:
    """Aggregate structured per-file coverage without collapsing skip reasons."""
    files = [report["coverage"] for report in reports]
    languages: dict[str, dict] = {}
    for row in files:
        language = row["language"]["id"] or "<unknown>"
        bucket = languages.setdefault(language, {
            "language": row["language"]["id"], "files": 0,
            "complete": 0, "partial": 0,
            "audit": row["language"]["audit"], "taint": row["language"]["taint"],
        })
        bucket["files"] += 1
        bucket[row["status"]] += 1
    skipped = [{"file": row["file"]["path"], "kind": kind, **rule}
               for row in files for kind, rules in row["rules"].items()
               for rule in rules["skipped"]]
    undecided = [{"file": row["file"]["path"], "kind": kind, **rule}
                 for row in files for kind, rules in row["rules"].items()
                 for rule in rules["undecided"]]
    return {
        "schema": "pegrex.scan-coverage-set.v1",
        "status": "partial" if any(row["status"] == "partial" for row in files) else "complete",
        "totals": {"files": len(files),
                   "complete": sum(row["status"] == "complete" for row in files),
                   "partial": sum(row["status"] == "partial" for row in files),
                   "skipped_rules": len(skipped), "undecided_rules": len(undecided)},
        "languages": [languages[key] for key in sorted(languages)],
        "files": files, "skipped_rules": skipped, "undecided_rules": undecided,
    }


def gate_exit(findings: list[dict], fail_on: str | None = None,
              fail_on_unknown: bool = False) -> int:
    """0 report/clean, 1 severity gate, 2 unknown-coverage gate."""
    active = [f for f in findings if not f.get("suppressed")]
    if fail_on_unknown and any(f.get("kind") == "unknown" for f in active):
        return 2
    if fail_on:
        threshold = SEV_ORDER[fail_on.upper()]
        if any(SEV_ORDER.get(f.get("severity", "INFO"), 4) <= threshold
               and f.get("kind") != "unknown" for f in active):
            return 1
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(prog="secaudit")
    ap.add_argument("file")
    ap.add_argument("--lang", default=None)
    output = ap.add_mutually_exclusive_group()
    output.add_argument("--json", action="store_true")
    output.add_argument("--sarif", action="store_true")
    ap.add_argument("--out", help="also write the selected report to this path")
    ap.add_argument("--fail-on", choices=[s.lower() for s in SEV_ORDER])
    ap.add_argument("--fail-on-unknown", action="store_true")
    a = ap.parse_args()
    report = audit_report(a.file, a.lang)
    findings = report["findings"]
    if a.sarif:
        from pegrex.export import to_sarif
        text = to_sarif(findings, provenance=report["provenance"])
        print(text)
    elif a.json:
        text = json.dumps(report, indent=1)
        print(text)
    else:
        text = ""
        for f in findings:
            suppressed = " SUPPRESSED" if f.get("suppressed") else ""
            print(f"{f['severity']:9} {f['confidence']:7} {f['id']:44} "
                  f"L{f['line']:<4} {f.get('kind', ''):8} {f['evidence']}{suppressed}")
        print(f"\ntotal: {len(findings)} findings; active: {report['active_total']}")
    if a.out:
        pathlib.Path(a.out).write_text(text if text else json.dumps(report, indent=1), encoding="utf-8")
    return gate_exit(findings, a.fail_on, a.fail_on_unknown)


if __name__ == "__main__":
    raise SystemExit(main())
