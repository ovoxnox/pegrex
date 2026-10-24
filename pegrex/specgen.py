"""
specgen

║  The AI debugging interface: one AST in, AgentReport out. 
║  parse -> guardrails -> CFG -> SSA -> path constraints -> solver -> spec."""

from __future__ import annotations

import json
from dataclasses import dataclass

from . import smt as _smt
from .cfg import CFGBuilder
from .paths import PathEnumerator
from .sym import Not
from .patterns import _tag, scan
from .peg import Node
from .specs import (AgentReport, PathReport, PreprocessSpec, PostprocessSpec,
                    State, Transition, Violation)
from .ssa import to_ssa


def _cond(cond, node, src):
    try:
        return cond(node, src)
    except TypeError:
        return cond(node)


def _pos(node):
    if getattr(node, "pos", None) is not None:
        return {"start": node.pos,
                "end": getattr(node, "endpos", getattr(node, "end_byte", None))}
    if getattr(node, "start_byte", None) is not None:
        return {"start": node.start_byte, "end": node.end_byte}
    return None


def _text_of(n):
    t = getattr(n, "text", None)
    if isinstance(t, bytes):
        return t.decode()
    if t:
        return str(t)
    ch = [c for c in getattr(n, "children", []) if _tag(c) is None]
    return str(ch[0]) if ch else None


def find_function(tree, name: str):
    """function_definition/declaration/item whose first child names `name`."""
    tags = ("function_definition", "function_declaration", "function_item")
    def walk(n):
        """walk(n): see module docstring."""
        if isinstance(n, Node):
            if _tag(n) in tags:
                kids = [c for c in n.children if _tag(c) is not None]
                if kids and _text_of(kids[0]) == name:
                    return n
            for c in n.children:
                if (r := walk(c)) is not None:
                    return r
        elif isinstance(n, list):
            for c in n:
                if (r := walk(c)) is not None:
                    return r
        return None
    return walk(tree)


def analyze(tree, language, entrypoint, rules=(), tagspec=None, src=None,
            cond=None, render=None, unroll: int = 2) -> AgentReport:
    """Run the full pipeline over a normalized AST; bind into the schema."""
    backend = _smt.get_backend()
    violations = [
        Violation(rule_id=rule.id or rule.node_type or "rule",
                  node_type=_tag(node),
                  position=_pos(node),
                  detail=json.dumps({k: (_tag(v[0]) if isinstance(v, tuple)
                                         else _tag(v))
                                     for k, v in (caps or {}).items()}),
                  severity="error")
        for node, rule, caps in scan(tree, rules, src)
    ]
    fn = find_function(tree, entrypoint)
    body = ([c for c in fn.children if _tag(c) is not None][-1] if fn else tree)
    cfg = CFGBuilder(tagspec).build(body)

    def assign_info(st):
        """assign info(st): see module docstring."""
        if not render:
            return None
        try:
            txt = render(st, src) if src is not None else render(st)
        except Exception:
            return None
        if txt and "=" in txt and "==" not in txt:
            var = txt.split("=")[0].strip()
            if var.isidentifier():
                return var, txt
        return None

    block_env, phis = to_ssa(cfg, assign_info)
    paths, sat = [], 0
    for pid, path in enumerate(PathEnumerator(cfg, unroll=unroll).enumerate()):
        cons = []
        for i in range(len(path) - 1):
            for dst, e in cfg.successors(path[i]):
                if dst != path[i + 1] or e.cond is None:
                    continue
                if cond and e.kind in ("then", "body"):
                    cons.append(str(_cond(cond, e.cond, src)))
                elif cond and e.kind in ("else", "exit"):
                    base = e.cond[0] if isinstance(e.cond, tuple) else e.cond
                    cons.append(str(Not(_cond(cond, base, src))))
        model = backend.learn(cons)
        ok = backend.feasible(model)
        sat += ok
        result = None
        for b in path:
            blk = cfg.blocks[b]
            if blk.term == "ret" and blk.stmts and render:
                try:
                    result = render(blk.stmts[0], src) if src is not None \
                        else render(blk.stmts[0])
                except Exception:
                    result = None
        env = {}
        for b in path:
            env |= {k: str(v) for k, v in block_env.get(b, {}).items()}
        paths.append(PathReport(path_id=pid, blocks=path,
                                constraints=sorted(set(cons)),
                                satisfiable=ok, result=result,
                                ssa_versions=env))
    states = [State(id=b.id, term=b.term) for b in cfg.blocks]
    transitions = [Transition(src=e.src, dst=e.dst,
                              guard=str(e.cond) if e.cond is not None else None)
                   for e in cfg.edges]
    assertions = []
    def _collect_asserts(n):
        if isinstance(n, Node):
            if n.tag == "assert_statement":
                txt = (src or "")[n.pos:n.endpos]
                assertions.append(txt.strip()[:120])
            for c in n.children:
                _collect_asserts(c)
        elif isinstance(n, list):
            for c in n:
                _collect_asserts(c)
    _collect_asserts(body)
    return AgentReport(
        language=language, entrypoint=entrypoint,
        states=states, transitions=transitions,
        assertions=sorted(set(assertions)),
        preprocess=PreprocessSpec(language=language, entrypoints=[entrypoint]),
        syntactic_violations=violations,
        ssa_phi_nodes=[{"block": b, "var": v, "incoming": inc}
                       for b, v, inc in phis],
        paths=paths,
        z3={"backend": type(backend).__name__, "paths_total": len(paths),
            "paths_satisfiable": sat, "paths_unsat": len(paths) - sat},
        postprocess=PostprocessSpec(invariants=[
            f"path {p.path_id} constraints must hold"
            for p in paths if p.satisfiable]))
