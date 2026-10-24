"""
paths

║  Path formulas: bounded enumeration over CFGs, SSA linearization,  
║  SMT-LIB export.  Every execution path becomes one formula."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .sym import Not, Op, Sym

NL = chr(10)


@dataclass
class PathFormula:
    """PathFormula - see module docstring."""
    blocks: list
    ssa: dict = field(default_factory=dict)
    constraints: list = field(default_factory=list)
    _SYM: "re.Pattern" = field(
        default=re.compile(r"(?<=[\s(])([A-Za-z_][\w@]*)"), repr=False)

    def smt2(self) -> str:
        """smt2(): see module docstring."""
        kw = {"not", "and", "or", "ite", "true", "false"}
        names = [n.replace("@", "_") for src in map(str, self.constraints)
                 for n in self._SYM.findall(src) if n not in kw]
        decls = NL.join(f"(declare-fun {n} () Int)" for n in dict.fromkeys(names))
        body = NL.join(f"(assert {str(c).replace('@', '_')})"
                       for c in self.constraints)
        return NL.join(["(set-logic QF_NIA)", decls, body, "(check-sat)", ""])


class PathEnumerator:
    """Enumerate CFG paths; loops unrolled at most `unroll` times."""

    def __init__(self, cfg, unroll: int = 2) -> None:
        self.cfg, self.unroll = cfg, unroll
        self._backs = {(e.src, e.dst) for e in cfg.edges if e.kind == "back"}

    def enumerate(self, entry: int = 0) -> list[list[int]]:"
        paths: list[list[int]] = []
        seen: set[tuple] = set()  # O(1) membership, not an O(P)
                                  # linear scan of `paths` itself

        def dfs(b: int, visits: dict, acc: tuple) -> None:
            acc += (b,)
            if self.cfg.blocks[b].term == "ret" or not self.cfg.successors(b):
                if acc not in seen:          # veritesting-lite: state merging
                    seen.add(acc)
                    paths.append(list(acc))  # identical paths collapse
                return
            for dst, e in self.cfg.successors(b):
                key = (e.src, e.dst)
                if key in self._backs and visits.get(key, 0) >= self.unroll:
                    continue
                v2 = dict(visits)
                if key in self._backs:
                    v2[key] = v2.get(key, 0) + 1
                dfs(dst, v2, acc)

        dfs(entry, {}, ())
        return paths


def _ssa_rename(expr, env):
    """Rewrite every Sym(name) leaf whose name has an SSA version in `env`
    to that version. Edge conditions come straight from the CFG using the
    source's bare variable names; without this, a condition evaluated after
    a reassignment earlier on this same path would silently mix the bare
    (stale) name with the later versioned symbols already in `cons` -- two
    different logical variables colliding under one name in one formula."""
    if isinstance(expr, Sym):
        return env.get(expr.name, expr)
    if isinstance(expr, Op):
        return Op(expr.op, tuple(_ssa_rename(a, env) for a in expr.args))
    return expr


def linearize(cfg, path, stmt_expr=None) -> PathFormula:
    """SSA-linearize one path into assignments + a constraint conjunction."""
    from .sym import Eq
    env, cons, version = {}, [], {}

    def fresh(n: str) -> str:
        """fresh(n): see module docstring."""
        version[n] = version.get(n, 0) + 1
        return f"{n}@{version[n]}"

    for i, b in enumerate(path):
        for st in cfg.blocks[b].stmts:
            if stmt_expr and (f := stmt_expr.get(st.tag)):
                nm, expr = f(st, env)
                env[nm] = Sym(fresh(nm))
                cons.append(Eq(env[nm], expr))
        if i + 1 < len(path):
            for dst, e in cfg.successors(b):
                if dst != path[i + 1] or e.cond is None:
                    continue
                if e.kind in ("then", "body"):
                    cons.append(_ssa_rename(e.cond, env))
                elif e.kind in ("else", "exit"):
                    c = e.cond[0] if isinstance(e.cond, tuple) else e.cond
                    cons.append(Not(_ssa_rename(c, env)))
    return PathFormula(list(path), env, cons)
