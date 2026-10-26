"""
assign

Assignment rendering + init extraction — feeds closed-form loop sums."""
from __future__ import annotations

import re

from .peg import Node

_AUG = re.compile(r"^([A-Za-z_]\w*)\s*(\+=|-=|\*=|/=)\s*(.+)$")
_INIT = re.compile(r"^([A-Za-z_]\w*)\s*=\s*(-?\d+)$")


def render_assignment(node: Node, src: str) -> str:
    """'s += i' -> canonical 's = s + i'."""
    txt = src[node.pos:node.endpos].strip()
    if (m := _AUG.match(txt)):
        var, op, rhs = m.groups()
        return f"{var} = {var} {op[0]} {rhs.strip()}"
    return txt


def numeric_inits(tree, src: str) -> dict[str, int]:
    """Implement numeric inits with the module's explicit API and failure semantics."""
    inits: dict[str, int] = {}

    def walk(n):
        """Implement walk with the module's explicit API and failure semantics."""
        if isinstance(n, Node):
            if n.tag == "assignment":
                txt = src[n.pos:n.endpos].strip()
                if (m := _INIT.match(txt)):
                    inits.setdefault(m.group(1), int(m.group(2)))
            for c in n.children:
                walk(c)
        elif isinstance(n, list):
            for c in n:
                walk(c)
    walk(tree)
    return inits


def loop_assignments(while_node: Node, src: str) -> list[str]:
    """Implement loop assignments with the module's explicit API and failure semantics."""
    out: list[str] = []

    def walk(n):
        """Implement walk with the module's explicit API and failure semantics."""
        if isinstance(n, Node):
            if n.tag in ("assignment", "augmented_assignment"):
                out.append(render_assignment(n, src))
                return
            for c in n.children:
                walk(c)
        elif isinstance(n, list):
            for c in n:
                walk(c)

    kids = [c for c in while_node.children if isinstance(c, Node)]
    body = next((k for k in kids if k.tag in ("block", "statement_list")),
                kids[1] if len(kids) >= 2 else None)
    if body is not None:
        walk(body)
    return out
