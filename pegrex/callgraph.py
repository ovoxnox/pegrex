"""
callgraph

Function-call graph extraction + visualization (DOT + ASCII).
Nodes are functions; edges are caller -> callee, resolved per scope."""

from __future__ import annotations

from dataclasses import dataclass, field

from .peg import Node


@dataclass
class CallGraph:
    """CallGraph - see module docstring."""
    functions: dict = field(default_factory=dict) # name -> {line, calls:set}
    edges: set = field(default_factory=set)       # (caller, callee)

    def to_dot(self) -> str:
        lines = ["digraph callgraph {", "  rankdir=LR;",
                 '  node [shape=box, style=rounded];']
        for name in sorted(self.functions):
            lines.append(f'  "{name}";')
        for caller, callee in sorted(self.edges):
            lines.append(f'  "{caller}" -> "{callee}";')
        lines.append("}")
        return chr(10).join(lines)

    def to_ascii(self) -> str:
        out = []
        for name in sorted(self.functions):
            callees = sorted(c for a, c in self.edges if a == name)
            mark = " -> " + ", ".join(callees) if callees else " (leaf)"
            out.append(f"{name}{mark}")
        return chr(10).join(out)


def build_call_graph(source: str, lang: str = "python",
                     all_functions: bool = True) -> CallGraph:
    """Extract the call graph from source.  Per-function bodies are walked;
    call nodes resolve to callee names (unresolved callees become '?'-free
    external nodes when external=True)."""
    import sys as _sys
    root = _sys.path and None
    import pipeline  # frontends
    if lang == "python":
        bodies = pipeline.python_functions(source)
        parse, tags, mk = pipeline.python_frontend()
        _ = parse  # noqa
        call_tag = "call"
    else:
        parse, tags, mk = pipeline.FRONTENDS[lang]()
        bodies = {"": parse(source)}
        call_tag = "call_expression" if lang in ("javascript", "typescript",
                                                 "solidity", "kotlin",
                                                 "zig") else "call"

    g = CallGraph()
    fn_names = set(bodies.keys()) if lang == "python" else set()
    if not fn_names:
        fn_names = set(bodies.keys())

    for fname, body in bodies.items():
        line = 0
        g.functions.setdefault(fname, {"line": line, "calls": set()})
        stack = [body]
        while stack:
            n = stack.pop()
            if isinstance(n, Node):
                if n.tag == call_tag:
                    callee = _callee_name(n, source)
                    if callee:
                        g.functions[fname]["calls"].add(callee)
                        g.edges.add((fname, callee))
                stack.extend(c for c in n.children
                             if isinstance(c, Node))
            elif isinstance(n, list):
                stack.extend(c for c in n if isinstance(c, Node))
    return g


def _callee_name(call_node: Node, source: str) -> str:
    """First identifier-ish child of the call = the callee name."""
    for c in call_node.children:
        if isinstance(c, str):
            return c.split("(")[0].strip() or ""
        if isinstance(c, Node):
            if c.tag in ("identifier", "attribute", "expression",
                         "field_expression", "call_expression"):
                txt = source[c.pos:c.endpos].strip()
                return txt.split("(")[0].split(".")[-1].strip() or ""
            txt = source[c.pos:c.endpos].strip()
            if txt and (txt[0].isalpha() or txt[0] == "_"):
                return txt.split("(")[0].split(".")[-1].strip()
    return ""
