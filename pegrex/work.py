"""
work.py -- compile .work agent-definition DSL files to ProjectSpec JSON.

    work quality_analyst { goal ...; workflow: [a -> b]; executors: { a: rule } }

->  {name, preprocess, postprocess.invariants, tasks-from-workflow}

The DSL is data; the engine is the executor."""

from __future__ import annotations

import json
import pathlib

from . import compile_grammar, peg
from .peg import Node as _N

_GRAMMAR = None


def _rules():
    global _GRAMMAR
    if _GRAMMAR is None:
        g = (pathlib.Path(__file__).parent.parent / "examples"
             / "agent.gram").read_text()
        _GRAMMAR = compile_grammar(g)
    return _GRAMMAR


def _text(node, src):
    if isinstance(node, _N):
        return src[node.pos:node.endpos].strip()
    return str(node).strip()


def _list(node, src):
    out = []
    def walk(n):
        if isinstance(n, str):
            v = n.strip()
            if v and v not in out:
                out.append(v)
            return
        if isinstance(n, _N):
            for c in n.children:
                walk(c)
    walk(node)
    return out


def compile_work(path: str) -> dict:
    start, rules = _rules()
    src = pathlib.Path(path).read_text()
    ast, err, pos = peg.run(start, src, rules)
    assert err is None, (err, pos)
    name0 = next((c for c in ast.children if isinstance(c, str)), None)
    spec = {"name": name0 or pathlib.Path(path).stem,
            "preprocess": {"language": "work",
                           "source_files": [path]},
            "tasks": [], "postprocess": {"invariants": []},
            "executors": {}}
    fields = {f.tag: f for f in ast.children if isinstance(f, _N)}
    for tag, key in (("Goal", "goal"), ("Memory", "memory")):
        if tag in fields:
            spec.setdefault("description", {})
            spec["description"][key] = _text(fields[tag].children[-1], src)
    for tag, key in (("Inputs", "inputs"), ("Outputs", "outputs"),
                     ("Tools", "tools")):
        if tag in fields:
            spec.setdefault("interface", {})[key] = _list(
                fields[tag], src)
    if "Invariants" in fields:
        spec["postprocess"]["invariants"] = _list(
            fields["Invariants"], src)
    if "Workflow" in fields:
        steps = _list(fields["Workflow"], src)
        spec["workflow_steps"] = steps
        spec["tasks"] = [{"order": i + 1, "priority": "P2",
                          "title": f"execute step '{s}'",
                          "verify": ["engine certificate"]}
                         for i, s in enumerate(steps)]
    if "Executors" in fields:
        kids = [c for c in fields["Executors"].children]
        for i in range(0, len(kids) - 1, 2):
            spec["executors"][str(kids[i]).strip()] = str(kids[i + 1]).strip()
    return spec


if __name__ == "__main__":
    import sys
    out = compile_work(sys.argv[1])
    print(json.dumps(out, indent=1))
