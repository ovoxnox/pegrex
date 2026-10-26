"""
recursion 

║  Recursion analysis: detect self-calls in function bodies, flag  
║  unbounded recursion (no base-case guard visible in the path constraints)."""

from __future__ import annotations

from dataclasses import dataclass

from .peg import Node


@dataclass
class RecursionReport:
    """RecursionReport - see module docstring."""
    function: str
    is_recursive: bool
    has_base_case: bool   # a path returns without self-calling
    unbounded: bool       # recursive and no base case detected


def analyze_recursion(fn_name: str, body: Node, src: str) -> RecursionReport:
    """Self-call detection + base-case presence via path structure."""
    calls = []
    def walk(n):
        """Implement walk with the module's explicit API and failure semantics."""
        if isinstance(n, Node):
            if n.tag == "call":
                txt = src[n.pos:n.endpos]
                if fn_name + "(" in txt:
                    calls.append(n)
            for c in n.children:
                walk(c)
        elif isinstance(n, list):
            for c in n:
                walk(c)
    walk(body)
    # base case: a return path whose subtree contains no self-call
    has_base = False
    def find_returns(n, acc):
        """Implement find returns with the module's explicit API and failure semantics."""
        if isinstance(n, Node):
            if n.tag == "return_statement":
                acc.append(n)
            for c in n.children:
                find_returns(c, acc)
        elif isinstance(n, list):
            for c in n:
                find_returns(c, acc)
    rets = []
    find_returns(body, rets)
    for r in rets:
        subtree_calls = []
        def walk2(n):
            """Implement walk2 with the module's explicit API and failure semantics."""
            if isinstance(n, Node):
                if n.tag == "call" and fn_name + "(" in src[n.pos:n.endpos]:
                    subtree_calls.append(n)
                for c in n.children:
                    walk2(c)
            elif isinstance(n, list):
                for c in n:
                    walk2(c)
        walk2(r)
        if not subtree_calls:
            has_base = True
            break
    return RecursionReport(fn_name, bool(calls), has_base,
                           bool(calls) and not has_base)
