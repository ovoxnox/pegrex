"""
wp -- weakest-precondition calculus 

║  WP(stmt, Q) walks a path backward from the postcondition Q, producing 
║  the weakest formula a state must satisfy for Q to hold after."""

from __future__ import annotations

from .sym import And, Not, Op, Sym


def wp_assign(var: str, expr, q) -> object:
    """WP(x := e, Q) = Q[e/x]  
            (substitution on expression trees)."""
    if isinstance(q, Sym):
        return expr if q.name == var else q
    if isinstance(q, Op):
        return Op(q.op, tuple(wp_assign(var, expr, a) for a in q.args))
    return q


def wp_path(stmts, post) -> object:
    """Backward fold over [ (var, expr), ... ] 
                assignments, then path guards."""
    q = post
    for var, expr in reversed(stmts):
        q = wp_assign(var, expr, q)
    return q


def wp_cond(guard, q_then, q_else) -> object:
    "WP(if g then S1 else S2, Q) = (g -> WP(S1,Q)) AND (not g -> WP(S2,Q))"
    return Op("or", (And(guard, q_then), And(Not(guard), q_else)))
