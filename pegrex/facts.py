"""facts.py -- datalog-style facts emission + tiny query evaluator.
Facts (calls, assigns, sinks, sources) over a parsed program; rules are
joins over facts -- fast, incremental, explainable (the CodeQL-lite seam)."""
from __future__ import annotations

import re


def collect_facts(source: str, lang: str = "python") -> dict:
    """{calls: [(f,g)], assigns: [(x, e)], sinks: [(line, name)]}."""
    import pipeline
    from pegrex.callgraph import build_call_graph
    from pegrex.peg import Node

    g = build_call_graph(source, lang)
    facts = {"calls": sorted(g.edges), "assigns": [], "sinks": []}
    parse, tags, mk = pipeline.FRONTENDS.get(lang, pipeline.python_frontend)()
    tree = None
    import tree_sitter_python
    from tree_sitter import Language, Parser
    try:
        root = Parser(Language(tree_sitter_python.language())).parse(
            source.encode()).root_node
        from pegrex.tree_sitter_bridge import ts_to_pegrex
        tree = ts_to_pegrex(root, source)
    except Exception:
        pass
    if tree is not None:
        stack = [tree]
        while stack:
            n = stack.pop()
            if isinstance(n, Node):
                if n.tag == "assignment":
                    txt = source[n.pos:n.endpos].strip()
                    m = re.match(r"([A-Za-z_]\w*)\s*=", txt)
                    if m:
                        facts["assigns"].append((m.group(1),
                                                 txt.split("=", 1)[1].strip()[:40]))
                for c in n.children:
                    if isinstance(c, Node):
                        stack.append(c)
            elif isinstance(n, list):
                stack.extend(c for c in n if isinstance(c, Node))
    for ln, line in enumerate(source.splitlines(), 1):
        for name in ("system", "eval", "exec", "popen"):
            if re.search(rf"\b{name}\s*\(", line):
                facts["sinks"].append((ln, name))
    return facts


def query(facts: dict, body: list) -> list:
    """Micro-datalog: body literals (rel, a, b) with '_' wildcards, joined.
    Returns tuples from the FIRST literal satisfying all others."""
    rels = {"calls": facts["calls"], "assigns": facts["assigns"],
            "sinks": facts["sinks"]}
    first = body[0]
    out = []
    for tup in rels.get(first[0], []):
        if first[1] not in ("_", tup[0]):
            continue
        if len(tup) > 1 and first[2] not in ("_", tup[1]):
            continue
        ok = True
        for rel, a, b in body[1:]:
            if not any((a in ("_", x[0])) and
                       (len(x) < 2 or b in ("_", x[1]))
                       for x in rels.get(rel, [])):
                ok = False
                break
        if ok:
            out.append(tup)
    return out
