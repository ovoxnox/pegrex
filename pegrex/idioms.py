"""
idioms

║  Guard-checked rewriting: source_tags + path_guard -> target template.    
║  A rewrite fires only when the SMT core proves the guard on a real path."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterator

from .peg import Node

_BIN_TXT = {"eq": "==", "lt": "<", "le": "<=", "gt": ">", "ge": ">=",
            "ne": "~=", "add": "+", "sub": "-", "mul": "*", "div": "/",
            "idiv": "//", "mod": "%", "pow": "^", "concat": "..",
            "unm": "-", "not": "not ", "len": "#", "bnot": "~"}


@dataclass(frozen=True)
class IdiomRule:
    name: str
    source_tags: tuple
    target_template: str
    path_guard: str | None = None
    slots: dict = field(default_factory=dict)   # slot -> child index


def _walk(node, path=()):
    yield node, path
    if isinstance(node, Node):
        for i, ch in enumerate(node.children):
            yield from _walk(ch, path + (i,))


def match_idioms(node, rules) -> Iterator[tuple[Node, IdiomRule]]:
    for n, _ in _walk(node):
        if isinstance(n, Node):
            for rule in rules:
                if n.tag in rule.source_tags:
                    yield n, rule


def guard_holds(rule: IdiomRule, constraints) -> bool:
    """Guard must be *implied* by at least one path's constraints (SMT)."""
    if not rule.path_guard:
        return True
    from .smt import learn, entails
    guard = rule.path_guard
    if (m := re.match(r"^\((<=|>=|<|>|=)\s+([A-Za-z_]\w*)\s+(-?\d+)\)$",
                     guard.strip())):      # tolerate SMT prefix style
        guard = f"({m.group(2)} {m.group(1)} {m.group(3)})"
    return any(entails(learn(path), guard) for path in constraints)


_SRC = ""


def _render(x) -> str:
    if isinstance(x, list):
        return " ".join(_render(i) for i in x)
    if not isinstance(x, Node):
        return str(x)
    # Tree-sitter nodes carry exact Python character spans. Prefer the source
    # expression over reconstructing operators and argument punctuation.
    if _SRC and 0 <= x.pos <= x.endpos <= len(_SRC):
        text = _SRC[x.pos:x.endpos].strip()
        if x.tag in ("Return", "return_statement", "jump-statement"):
            return re.sub(r"^return\b", "", text).strip().rstrip(";")
        if x.tag not in ("Block", "block", "compound-statement", "else_clause",
                         "consequence", "alternative") and text:
            return text
    if x.tag in ("Id", "identifier") and x.children:
        return str(x.children[0])
    if x.tag == "Number":
        return str(x.children[0])
    if x.tag == "Call":
        kids = list(x.children)
        fn = kids[-1] if kids else "?"
        args = kids[0] if len(kids) > 1 else []
        return f"{_render(fn)}({_render(args)})"
    if x.tag == "Return":
        kids = [c for c in x.children]
        return _render(kids[0]) if kids else ""
    if x.tag == "Block":
        inner = [_render(c) for c in x.children if isinstance(c, Node)]
        return inner[0] if len(inner) == 1 else " ".join(inner)
    if x.tag in ("BinaryOp", "UnaryOp"):
        p = x.children
        if len(p) >= 3:
            return f"{_render(p[0])} {_BIN_TXT.get(p[1], p[1])} {_render(p[2])}"
    if x.tag in ("comparison_operator", "binary_operator"):  # op is anonymous
        import re as _re
        span = _SRC[x.pos:x.endpos]
        m = _re.search(r"(<=|>=|==|!=|<|>|\+|-|\*|/)", span)
        op = m.group(1) if m else "?"
        p = x.children
        if len(p) >= 2:
            return f"{_render(p[0])} {op} {_render(p[1])}"
    if x.tag == "call":  # python: [fn, argument_list]
        kids = list(x.children)
        fn = _render(kids[0]) if kids else "?"
        args = " ".join(_render(c) for c in kids[1:])
        return f"{fn}({args})"
    if x.tag == "return_statement":
        return " ".join(_render(c) for c in x.children)
    inner = " ".join(_render(c) if isinstance(c, (Node, list)) else str(c)
                     for c in x.children)
    return inner or x.tag


def apply_template(rule: IdiomRule, node: Node) -> str:
    """apply template(rule, node): see module docstring."""
    nodes = [c for c in node.children if isinstance(c, Node)]
    vals = {slot: (_render(nodes[idx]) if idx < len(nodes) else "?")
            for slot, idx in rule.slots.items()}
    return rule.target_template.format(**vals)


def translate(node, rules, constraints, src: str = "") -> list[tuple[str, str]]:
    """translate(node, rules, constraints, src): see module docstring."""
    global _SRC
    _SRC = src
    """(rule_name, rendered_target) for every rule whose tag matched AND
    whose path guard is proven on this function's constraints."""
    return [(rule.name, apply_template(rule, n))
            for n, rule in match_idioms(node, rules)
            if guard_holds(rule, constraints)]
