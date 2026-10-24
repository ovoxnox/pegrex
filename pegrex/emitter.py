"""
emitter — real code from the contract IR (core slice) 

║  Path contracts (constraints -> result, straight-line branches) become   
║  real Python source. Emission is not trusted: the emitted function must  
║  pass verify_patch against the original or it is refused."""

from __future__ import annotations

from .ir import lower_condition, parse_expr, to_sym
from .sym import Op, Sym


def emit_sym(e) -> str:
    """sym tree -> Python expression text (the linear/boolean fragment)."""
    if isinstance(e, Sym):
        return e.name
    if isinstance(e, bool):
        return "True" if e else "False"
    if isinstance(e, int):
        return str(e)
    if isinstance(e, Op):
        op = e.op
        a = e.args
        if op == "not":
            return f"(not ({emit_sym(a[0])}))"
        if op in ("and", "or"):
            join = f" {op} "
            return "(" + join.join(f"({emit_sym(x)})" for x in a) + ")"
        if op == "=":
            return f"({emit_sym(a[0])} == {emit_sym(a[1])})"
        if len(a) == 1:                      # unary minus
            return f"(-{emit_sym(a[0])})"
        if op == "-" and a[0] == 0:
            return f"(-{emit_sym(a[1])})"    # 0 - n  ==>  -n
        if op in ("+", "-", "*", "<", "<=", ">", ">=", "==", "!="):
            return f"({emit_sym(a[0])} {op} {emit_sym(a[1])})"
    raise ValueError(f"emitter: cannot emit {e!r}")


def emit_python(fn_name: str, params: list, contracts) -> str:
    """contracts: [(frozenset(sym-constraints), result-sym)] from api.contracts.

    Straight-line branch code: one `if` per non-final path, bare return for
    the last. Only the branchy-linear fragment is emitted; anything else
    refuses loudly."""
    paths = [(sorted(cs, key=str), res) for cs, res in contracts]
    if not paths:
        raise ValueError("emitter: no contracts, nothing to emit")
    for cs, res in paths:
        for c in cs:
            emit_sym(lower_condition(str(c)))   # strings -> sym -> Python
        emit_sym(to_sym(parse_expr(str(res))))
    # exhaustiveness: the emitted if/else chain must cover the space.
    # probe = conjunction of all negated guards; infeasible => exhaustive.
    from .linsolve import LinearBackend
    from .refine import _neg
    lb = LinearBackend()
    neg_atoms = []
    for cs, _ in paths:
        for c in cs:
            try:
                from .ir import cond_to_atom
                neg_atoms.append(cond_to_atom(_neg(lower_condition(str(c)))))
            except Exception:
                neg_atoms = []
                break
    exhaustive = False
    if neg_atoms:
        probe = lb.learn(neg_atoms)
        exhaustive = not probe.feasible()
    if not exhaustive:
        raise ValueError("emitter: path guards not proven exhaustive -- "
                         "refusing to emit a partial function")

    lines = [f"def {fn_name}({', '.join(params)}):"]
    for i, (cs, res) in enumerate(paths):
        cond = " and ".join(emit_sym(lower_condition(str(c))) for c in cs) \
               if cs else "True"
        ret = emit_sym(to_sym(parse_expr(str(res))))
        kw = "if" if i == 0 else ("elif" if i < len(paths) - 1 else "else")
        if kw == "else":
            lines.append(f"    else:")
        else:
            lines.append(f"    {kw} {cond}:")
        lines.append(f"        return {ret}")
    return "\n".join(lines) + "\n"
