"""
twin - digital twin of a codebase

A queryable graph: functions (nodes), call edges, ownership annotations
('# owner: NAME'), and sink guards. Questions are answered with PATH
MATH: 'which functions reach sink S' = reverse reachability through call
edges with each entry's guard constraints from the real path contracts.
Unknown question shapes refuse loudly -- the twin never invents an
answer.
"""
from __future__ import annotations

import os
import re

from . import api

_FN = {
    "python": r"^def\s+(\w+)\s*\(",
    "go": r"^func\s+(?:\(\w+\s+[\w.]+\)\s+)?(\w+)\s*\(",
    "rust": r"^\s*(?:pub\s+)?(?:async\s+)?fn\s+(\w+)",
    "zig": r"^\s*(?:pub\s+)?fn\s+(\w+)",
    "javascript": r"^\s*(?:async\s+)?function\s+(\w+)\s*\(",
    "typescript": r"^\s*(?:async\s+)?function\s+(\w+)\s*\(",
    "tsx": r"^\s*(?:async\s+)?function\s+(\w+)\s*\(",
    "julia": r"^function\s+(\w+)",
    "kotlin": r"^\s*(?:fun|class)\s+(\w+)",
    "solidity": r"^\s*function\s+(\w+)\s*\(",
    "fortran": r"^\s*(?:\w+\s+)?function\s+(\w+)\s*\(",
    "cobol": r"^\s*(?:\d+\s+)?([A-Z][A-Z0-9-]+)\s*\.$",
}
_EXT = {".py": "python", ".go": "go", ".rs": "rust", ".zig": "zig",
        ".js": "javascript", ".ts": "typescript", ".tsx": "tsx",
        ".jl": "julia", ".kt": "kotlin", ".sol": "solidity",
        ".f90": "fortran", ".f95": "fortran", ".f03": "fortran",
        ".f08": "fortran", ".cob": "cobol", ".cbl": "cobol"}


def _lang_of(path):
    return _EXT.get(os.path.splitext(path)[1].lower(), "python")


def build(root):
    """root: directory of sources -> twin graph dict (any supported
    language, detected per file by extension)."""
    from .callgraph import build_call_graph
    from .annotations import comment_prefix
    fns, calls, owners, files = set(), {}, {}, {}
    for dirpath, _, names in os.walk(root):
        for n in sorted(names):
            lang = _EXT.get(os.path.splitext(n)[1].lower())
            if lang is None or lang == "cobol" or lang == "fortran":
                continue
            path = os.path.join(dirpath, n)
            src = open(path, encoding="utf-8").read()
            g = build_call_graph(src, lang=lang)
            got = {n: i for n, i in g.functions.items() if n}
            if got:
                for name, info in got.items():
                    fns.add(name)
                    files[name] = path
                    calls[name] = sorted(info["calls"])
            else:
                calls = dict(calls)
            fn_rx = re.compile(_FN.get(lang, _FN["python"]), re.M)
            owner_rx = re.compile(
                re.escape(comment_prefix(lang)) + r"\s*owner:\s*([\w-]+)")
            matches = list(fn_rx.finditer(src))
            for i, m in enumerate(matches):
                name = next((g for g in m.groups() if g), None)
                if name is None:
                    continue
                block_start = matches[i - 1].end() if i > 0 else 0
                block_end = (matches[i + 1].start()
                             if i + 1 < len(matches) else len(src))
                block = src[block_start:block_end]
                om = owner_rx.search(block)
                owners[name] = om.group(1) if om else None
                fns.add(name)
                files.setdefault(name, path)
                if name not in calls:
                    body = src[m.end():block_end]
                    calls[name] = sorted({c for c in re.findall(
                        r"\b(\w+)\s*\(", body)
                        if c not in ("if", "for", "while", "switch", "return",
                                     "func", "function", "fn", "fun")})
    return {"functions": sorted(fns), "calls": calls, "owners": owners,
            "files": files, "root": root}


def reach(twin, sink):
    """Functions that can reach sink, directly or transitively."""
    rev = {}
    for f, cs in twin["calls"].items():
        for c in cs:
            rev.setdefault(c, set()).add(f)
    seen, stack = set(), sorted(rev.get(sink, ()))
    while stack:
        f = stack.pop()
        if f in seen:
            continue
        seen.add(f)
        stack.extend(rev.get(f, ()))
    return sorted(seen)


def guard_for(twin, fn, sink):
    """Guard constraints on fn's paths (from the real path contracts)."""
    path = twin["files"].get(fn)
    if not path:
        return None
    return [sorted(map(str, cs)) for cs, _ in api.contracts(path)]


_QLIB = [
    (re.compile(r"which functions (?:can reach|call|use)\s*(?:sink\s*)?(\w+)",
                re.I), "reach"),
    (re.compile(r"which functions are (?:over|above) (?:the )?budget",
                re.I), "cognitive"),
]


def cognitive_report(twin, budget=7):
    """Per-function cognitive complexity across the twin's files."""
    from .cognitive import cognitive_complexity
    out = []
    seen = set()
    for fn, path in twin["files"].items():
        if path in seen:
            continue
        seen.add(path)
        rep = cognitive_complexity(open(path, encoding="utf-8").read(), budget=budget)
        if rep.get("verdict") != "ok":
            out.append({"file": path, "verdict": "unknown",
                        "reason": rep.get("reason")})
            continue
        for f in rep["functions"]:
            out.append({"function": f["name"], "file": path,
                        "complexity": f["complexity"],
                        "over_budget": f["complexity"] > budget,
                        "refactor_plans": f["refactor_plans"]})
    return out


def ask(twin, question):
    """NL question -> answer dict. Unknown shapes refuse loudly."""
    for rx, kind in _QLIB:
        m = rx.search(question)
        if not m:
            continue
        if kind == "reach":
            target = m.group(1)
            rs = reach(twin, target)
            return {"kind": "reach", "target": target,
                    "functions": rs,
                    "guards": {f: guard_for(twin, f, target) for f in rs}}
        if kind == "cognitive":
            return {"kind": "cognitive", "functions": cognitive_report(twin)}
    raise ValueError(f"twin: unknown question shape {question!r}")
