"""
synthesize -- programs from constraints (Sketch-style) 

║  Given path constraints as a spec, enumerate small expression programs 
║  and keep those whose evaluation satisfies the formula."""

from __future__ import annotations

import itertools

from .smt import learn


def _eval(expr, env):
    if isinstance(expr, (int, float)):
        return expr
    if isinstance(expr, str):
        return env.get(expr, 0)
    op, a, b = expr
    va, vb = _eval(a, env), _eval(b, env)
    return {"+": va + vb, "-": va - vb, "*": va * vb,
            "<": va < vb, ">": va > vb, "<=": va <= vb,
            ">=": va >= vb, "==": va == vb}[op]


def _atoms_str(model, result):
    """Check result-env satisfies the learned model's bounds."""
    m = learn(model)
    for var, (lo, li, hi, hi_inc, neq) in m.bounds.items():
        v = result.get(var)
        if v is None:
            continue
        if lo is not None and (v < lo or (v == lo and not li)):
            return False
        if hi is not None and (v > hi or (v == hi and not hi_inc)):
            return False
        if v in neq:
            return False
    return True


def synthesize(model_atoms, vars=("a", "b"), consts=(1, 2, 3), max_depth=2,
               limit=5) -> list:
    """Small expression enumerator; keep programs satisfying the model."""
    exprs = list(consts) + list(vars)
    out = []
    for depth in range(max_depth):
        for op in ("+", "-", "*"):
            for x, y in itertools.product(exprs, repeat=2):
                e = (op, x, y)
                env = {v: i + 1 for i, v in enumerate(vars)}
                if _atoms_str(model_atoms, env) and _eval(e, env) is not None:
                    out.append(e)
                if len(out) >= limit:
                    return out
        exprs = exprs + out[:20]
    return out[:limit]
