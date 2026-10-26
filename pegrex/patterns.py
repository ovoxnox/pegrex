"""
patterns 

║  Native syntactic guardrails — Semgrep-style structural matching.  
║  Rules are data: node type + span-regex + child shapes + where-clauses."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterator

from .peg import Node


@dataclass(frozen=True)
class Pattern:
    """One guardrail rule. All fields optional; the and of what you set."""
    node_type: str | None = None
    text: str | None = None                # regex over the node's source span
    children: tuple["Pattern", ...] = ()   # positional child patterns
    capture: dict[str, Any] = field(default_factory=dict)   # name -> child idx|Pattern
    where: Callable[[dict], bool] | None = None # final predicate over captures
    id: str | None = None

    def compiled(self) -> "re.Pattern[str] | None":
        """Implement compiled with the module's explicit API and failure semantics."""
        return re.compile(self.text) if isinstance(self.text, str) else None


def _tag(node) -> str | None:
    return getattr(node, "tag", None) or getattr(node, "type", None)


def _text(node, src: str | None) -> str | None:
    t = getattr(node, "text", None)
    if t is not None:
        return t.decode() if isinstance(t, bytes) else t
    if src is not None:
        s = getattr(node, "start_byte", getattr(node, "pos", None))
        e = getattr(node, "end_byte", getattr(node, "endpos", None))
        if s is not None and e is not None:
            return src[s:e]
    return None


def match(node, pat: Pattern, src: str | None = None,
          captures: dict | None = None) -> dict | None:
    """The five checks: type, text, children, captures, where. AND-composed."""
    caps = {} if captures is None else captures

    if pat.node_type and _tag(node) != pat.node_type:
        return None
    if pat.text is not None:
        txt = _text(node, src)
        if txt is None or not (rx := pat.compiled()).search(txt):
            return None
    kids = [c for c in getattr(node, "children", []) if _tag(c) is not None]
    for i, cp in enumerate(pat.children):
        if i >= len(kids) or (sub := match(kids[i], cp, src, dict(caps))) is None:
            return None
        caps |= sub
    for name, idx in pat.capture.items():
        if isinstance(idx, int) and idx < len(kids):
            caps[name] = kids[idx]
        elif isinstance(idx, Pattern):
            hit = next((match(k, idx, src) for k in kids if match(k, idx, src)), None)
            if hit is None:
                return None
            caps[name] = hit
    if pat.where and not pat.where(caps):
        return None
    return caps


def scan(tree, rules: list[Pattern], src: str | None = None
         ) -> Iterator[tuple[object, Pattern, dict]]:
    """DFS(tree) × rules. Yields (node, rule, captures) per hit."""

    def walk(n):
        """Implement walk with the module's explicit API and failure semantics."""
        yield n
        for c in getattr(n, "children", []) or []:
            if _tag(c) is not None:
                yield from walk(c)

    for node in walk(tree):
        for rule in rules:
            if (caps := match(node, rule, src)) is not None:
                yield node, rule, caps
