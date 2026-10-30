"""
annotations - comment syntax map shared across analyzers.

One table: language -> comment prefix. Consumers (compliance, refine,
twin, orgtwin) read annotations like "pii:", "sink:", "owner:" without
hardcoding "#". Unknown languages refuse loudly.
"""
from __future__ import annotations

import io
import re
import tokenize

from .languages import LANGUAGES, detect_language

COMMENT_PREFIX = {name: spec.comment_prefix for name, spec in LANGUAGES.items()
                  if spec.comment_prefix is not None}
_TS_LANGS = {name for name, spec in LANGUAGES.items()
             if spec.parser.startswith("tree-sitter") and "contracts" in spec.capabilities}


def comment_prefix(lang: str) -> str:
    """Implement comment prefix with the module's explicit API and failure semantics."""
    from .languages import normalize_language
    resolved = normalize_language(lang)
    if resolved is None or resolved not in COMMENT_PREFIX:
        raise ValueError(f"annotations: no comment syntax for {lang!r}")
    return COMMENT_PREFIX[resolved]


def _annotation_matches(src: str, lang: str, rx: re.Pattern) -> list[re.Match]:
    """Match real Python comments, not comment-looking text inside strings."""
    from .languages import normalize_language
    if normalize_language(lang) != "python":
        return list(rx.finditer(src))
    comments = []
    try:
        for token in tokenize.generate_tokens(io.StringIO(src).readline):
            if token.type == tokenize.COMMENT:
                comments.append(token.string)
    except (tokenize.TokenError, IndentationError):
        # Annotation extraction remains available for incomplete source; only
        # tokenizer-confirmed comments collected before the error are used.
        pass
    return [match for comment in comments for match in rx.finditer(comment)]


def annotated(src: str, lang: str, tag: str, needs: str | None = None):
    """Values of `prefix <tag>: value` annotation lines.
    needs="consent" marks consent-gated entries (compliance)."""
    p = re.escape(comment_prefix(lang))
    rx = re.compile(p + r"\s*" + re.escape(tag) + r":\s*(.+?)\s*$", re.M)
    return [m.group(1).strip() for m in _annotation_matches(src, lang, rx)]


def annotations(src: str, lang: str):
    """All recognized annotations in one pass: {tag: [values]}."""
    p = re.escape(comment_prefix(lang))
    rx = re.compile(p + r"\s*(pii|sink|consent|owner|requires|ensures):\s*(.+?)\s*$", re.M)
    out: dict = {}
    for m in _annotation_matches(src, lang, rx):
        out.setdefault(m.group(1), []).append(m.group(2).strip())
    return out


def language_of(path: str) -> str:
    """Implement language of with the module's explicit API and failure semantics."""
    lang = detect_language(path)
    if lang is None:
        raise ValueError(f"annotations: unknown language for {path!r}")
    return lang