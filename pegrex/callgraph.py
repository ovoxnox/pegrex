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
        """Implement to dot with the module's explicit API and failure semantics."""
        lines = ["digraph callgraph {", "  rankdir=LR;",
                 '  node [shape=box, style=rounded];']
        for name in sorted(self.functions):
            lines.append(f'  "{name}";')
        for caller, callee in sorted(self.edges):
            lines.append(f'  "{caller}" -> "{callee}";')
        lines.append("}")
        return chr(10).join(lines)

    def to_ascii(self) -> str:
        """Implement to ascii with the module's explicit API and failure semantics."""
        out = []
        for name in sorted(self.functions):
            callees = sorted(c for a, c in self.edges if a == name)
            mark = " -> " + ", ".join(callees) if callees else " (leaf)"
            out.append(f"{name}{mark}")
        return chr(10).join(out)


def build_call_graph(source: str, lang: str = "python",
                     all_functions: bool = True, *, tree=None) -> CallGraph:
    """Extract the call graph from source.  Per-function bodies are walked;
    call nodes resolve to callee names (unresolved callees become '?'-free
    external nodes when external=True)."""
    import sys as _sys
    root = _sys.path and None
    import pipeline
    from .languages import normalize_language, get_language
    normalized = normalize_language(lang)
    if normalized is None:
        raise ValueError(f"unsupported call-graph language {lang!r}")
    spec = get_language(normalized)
    if "callgraph" not in spec.capabilities:
        raise NotImplementedError(f"call graph unsupported for {normalized}: {spec.notes}")
    if normalized == "python":
        bodies = pipeline.python_functions(source, tree=tree)
        call_tags = {"call", "call_expression"}
    else:
        if tree is None:
            parse, tags, mk = pipeline.frontend_for(normalized)
            tree = parse(source)
        bodies = {"": tree}
        call_tags = {"call_expression", "call"}

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
                if n.tag in call_tags:
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
