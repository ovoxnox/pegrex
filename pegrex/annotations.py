"""
annotations - comment syntax map shared across analyzers.

One table: language -> comment prefix. Consumers (compliance, refine,
twin, orgtwin) read annotations like "pii:", "sink:", "owner:" without
hardcoding "#". Unknown languages refuse loudly.
"""
from __future__ import annotations

import re

COMMENT_PREFIX = {
    "python": "#",
    "julia": "#",
    "go": "//", "rust": "//", "javascript": "//", "typescript": "//",
    "tsx": "//", "kotlin": "//", "zig": "//", "solidity": "//", "c": "//",
    "cobol": "*>", "fortran": "!",
}

_TS_LANGS = {"go", "rust", "javascript", "typescript", "tsx", "julia",
             "kotlin", "zig", "solidity"}


def comment_prefix(lang: str) -> str:
    if lang not in COMMENT_PREFIX:
        raise ValueError(f"annotations: no comment syntax for {lang!r}")
    return COMMENT_PREFIX[lang]


def annotated(src: str, lang: str, tag: str, needs: str | None = None):
    """Values of `prefix <tag>: value` annotation lines.
    needs="consent" marks consent-gated entries (compliance)."""
    p = re.escape(comment_prefix(lang))
    rx = re.compile(p + r"\s*" + re.escape(tag) + r":\s*(.+?)\s*$", re.M)
    return [m.group(1).strip() for m in rx.finditer(src)]


def annotations(src: str, lang: str):
    """All recognized annotations in one pass: {tag: [values]}."""
    p = re.escape(comment_prefix(lang))
    rx = re.compile(p + r"\s*(pii|sink|consent|owner|requires|ensures):\s*(.+?)\s*$", re.M)
    out: dict = {}
    for m in rx.finditer(src):
        out.setdefault(m.group(1), []).append(m.group(2).strip())
    return out


def language_of(path: str) -> str:
    from .api import _EXT_LANG
    import os
    ext = os.path.splitext(path)[1].lower()
    if ext in _EXT_LANG:
        return _EXT_LANG[ext]
    if ext == ".py":
        return "python"
    if ext in (".js", ".jsx"):
        return "javascript"
    if ext == ".ts":
        return "typescript"
    if ext == ".tsx":
        return "tsx"
    if ext in (".rs", ".go", ".jl", ".kt", ".zig", ".sol", ".c", ".h"):
        return {".rs": "rust", ".go": "go", ".jl": "julia", ".kt": "kotlin",
                ".zig": "zig", ".sol": "solidity", ".c": "c", ".h": "c"}[ext]
    raise ValueError(f"annotations: unknown language for {path!r}")