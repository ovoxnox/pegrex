"""
paths

║  Path formulas: bounded enumeration over CFGs, SSA linearization,  
║  SMT-LIB export.  Every execution path becomes one formula."""

from __future__ import annotations

import re
import time
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


@dataclass
class PathEnumeration:
    """Complete paths or an explicit resource UNKNOWN, never a partial proof."""
    paths: list[list[int]]
    complete: bool
    unknowns: list[str] = field(default_factory=list)
    visited: int = 0

    @property
    def verdict(self) -> str:
        return "ok" if self.complete else "unknown"


class PathExplosion(RuntimeError):
    """Legacy list API cannot represent incomplete enumeration safely."""


class PathEnumerator:
    """Enumerate CFG paths deterministically with optional resource limits."""

    def __init__(self, cfg, unroll: int = 2, *, max_paths: int | None = None,
                 timeout_ms: int | None = None) -> None:
        self.cfg, self.unroll = cfg, unroll
        self.max_paths, self.timeout_ms = max_paths, timeout_ms
        self._backs = {(e.src, e.dst) for e in cfg.edges if e.kind == "back"}

    def enumerate_bounded(self, entry: int = 0, *, max_paths: int | None = None,
                          timeout_ms: int | None = None) -> PathEnumeration:
        cap = self.max_paths if max_paths is None else max_paths
        timeout = self.timeout_ms if timeout_ms is None else timeout_ms
        deadline = time.monotonic() + timeout / 1000 if timeout is not None else None
        paths: list[list[int]] = []
        seen: set[tuple] = set()
        unknowns: list[str] = []
        visited = 0

        def dfs(block: int, visits: dict, acc: tuple) -> None:
            nonlocal visited
            if unknowns:
                return
            visited += 1
            if deadline is not None and time.monotonic() > deadline:
                unknowns.append(f"path enumeration exceeded {timeout}ms")
                return
            acc += (block,)
            successors = sorted(self.cfg.successors(block),
                                key=lambda item: (item[0], item[1].kind, str(item[1].cond)))
            if self.cfg.blocks[block].term == "ret" or not successors:
                if acc not in seen:
                    if cap is not None and len(paths) >= cap:
                        unknowns.append(f"path count cap {cap} exceeded")
                        return
                    seen.add(acc)
                    paths.append(list(acc))
                return
            for dst, edge in successors:
                key = (edge.src, edge.dst)
                if key in self._backs and visits.get(key, 0) >= self.unroll:
                    continue
                next_visits = dict(visits)
                if key in self._backs:
                    next_visits[key] = next_visits.get(key, 0) + 1
                dfs(dst, next_visits, acc)
                if unknowns:
                    return

        dfs(entry, {}, ())
        complete = not unknowns
        return PathEnumeration(paths if complete else [], complete, unknowns, visited)

    def enumerate(self, entry: int = 0) -> list[list[int]]:
        result = self.enumerate_bounded(entry)
        if not result.complete:
            raise PathExplosion("; ".join(result.unknowns))
        return result.paths


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
