"""
gramir

║  The grammar DSL as data. Lift a compiled pattern tree into an editable  
║  IR, transform it programmatically, lower it back — or serialize to DSL   
║  text.  This is the native replacement for hand-editing grammar files:    
║  rules are objects; refactorings are tree transforms."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from . import compiler
from . import peg
from .peg import (AltP, AndP, AnyP, BackP, CapP, CmtP, CpP, CsP, CtP, Eps,
                  EqBackP, FoldP, FuncP, GroupP, Lit, NodeP, NotP, RepP,
                  SeqP, SetP, ThrowP, ValP, V)


@dataclass
class IR:
    """One pattern node in the grammar IR."""
    kind: str
    args: tuple = ()
    value: Any = None


def lift(p: peg.Patt) -> IR:
    """Compiled pattern tree -> IR (lossless for the lifted subset)."""
    if isinstance(p, Lit):
        return IR("lit", value=p.text)
    if isinstance(p, AnyP):
        return IR("any")
    if isinstance(p, SetP):
        return IR("set", value=(tuple(map(_freeze, p.items)), p.complement))
    if isinstance(p, Eps):
        return IR("eps")
    if isinstance(p, SeqP):
        return IR("seq", tuple(lift(x) for x in p.ps))
    if isinstance(p, AltP):
        return IR("alt", tuple(lift(x) for x in p.ps))
    if isinstance(p, RepP):
        return IR("rep", (lift(p.p),), (p.lo, p.hi))
    if isinstance(p, NotP):
        return IR("not", (lift(p.p),))
    if isinstance(p, AndP):
        return IR("and", (lift(p.p),))
    if isinstance(p, CapP):
        return IR("cap", (lift(p.p),))
    if isinstance(p, CsP):
        return IR("cs", (lift(p.p),))
    if isinstance(p, CtP):
        return IR("ct", (lift(p.p),))
    if isinstance(p, CpP):
        return IR("pos")
    if isinstance(p, ValP):
        return IR("val", value=_freeze(p.value))
    if isinstance(p, FuncP):
        return IR("func", (lift(p.p),), getattr(p.fn, "__name__", "fn"))
    if isinstance(p, CmtP):
        return IR("cmt", (lift(p.p),), getattr(p.fn, "__name__", "fn"))
    if isinstance(p, FoldP):
        return IR("fold", (lift(p.p),), getattr(p.fn, "__name__", "fn"))
    if isinstance(p, GroupP):
        return IR("group", (lift(p.p),), p.name)
    if isinstance(p, BackP):
        return IR("back", value=p.name)
    if isinstance(p, EqBackP):
        return IR("eqback", value=p.name)
    if isinstance(p, ThrowP):
        return IR("throw", value=p.label)
    if isinstance(p, NodeP):
        return IR("node", (lift(p.p),), p.tag)
    if isinstance(p, V):
        return IR("ref", value=p.name)
    return IR("opaque", value=repr(p)[:60])


def _freeze(x):
    if isinstance(x, list):
        return tuple(_freeze(i) for i in x)
    if isinstance(x, dict):
        return tuple(sorted((_freeze(k), _freeze(v)) for k, v in x.items()))
    return x


def lower(ir: IR) -> peg.Patt:
    """IR -> compiled pattern (reuses the engine; refs resolved at match)."""
    k, a, v = ir.kind, ir.args, ir.value
    if k == "lit":
        return Lit(v)
    if k == "any":
        return AnyP()
    if k == "set":
        return SetP(list(v[0]), v[1])
    if k == "eps":
        return Eps()
    if k == "seq":
        return SeqP(*(lower(x) for x in a))
    if k == "alt":
        return AltP(*(lower(x) for x in a))
    if k == "rep":
        return RepP(lower(a[0]), v[0], v[1])
    if k == "not":
        return NotP(lower(a[0]))
    if k == "and":
        return AndP(lower(a[0]))
    if k == "cap":
        return CapP(lower(a[0]))
    if k == "cs":
        return CsP(lower(a[0]))
    if k == "ct":
        return CtP(lower(a[0]))
    if k == "pos":
        return CpP()
    if k == "val":
        return ValP(v)
    if k == "func":
        return FuncP(lower(a[0]), _resolve(v))
    if k == "cmt":
        return CmtP(lower(a[0]), _resolve(v))
    if k == "fold":
        return FoldP(lower(a[0]), _resolve(v))
    if k == "group":
        return GroupP(v, lower(a[0]))
    if k == "back":
        return BackP(v)
    if k == "eqback":
        return EqBackP(v)
    if k == "throw":
        return ThrowP(v)
    if k == "node":
        return NodeP(v, lower(a[0]))
    if k == "ref":
        return V(v)
    raise ValueError(f"cannot lower IR kind {k!r}")


def _resolve(name: str):
    """Resolve a lifted function name against the compiler prelude/defs."""
    if name in compiler.PRELUDE and callable(compiler.PRELUDE[name]):
        return compiler.PRELUDE[name]
    raise GrammarErrorLookup(name)


class GrammarErrorLookup(Exception):
    pass


def to_dsl(ir: IR, indent: int = 0) -> str:
    """IR -> lpegrex DSL text fragment (round-trippable for the lifted set)."""
    k, a, v = ir.kind, ir.args, ir.value
    if k == "lit":
        return "'" + str(v).replace("'", "") + "'"
    if k == "any":
        return "."
    if k == "eps":
        return "''"
    if k == "ref":
        return v
    if k == "val":
        return "$" + (repr(v) if isinstance(v, str) else str(v).lower()
                      if isinstance(v, bool) else str(v))
    if k == "throw":
        return "%{" + v + "}" if not v.startswith("Expected") else "@" + v[8:]
    if k == "pos":
        return "{}"
    if k == "not":
        return "!" + to_dsl(a[0])
    if k == "and":
        return "&" + to_dsl(a[0])
    if k == "cap":
        return "{" + to_dsl(a[0]) + "}"
    if k == "cs":
        return "{~" + to_dsl(a[0]) + "~}"
    if k == "ct":
        return "{|" + to_dsl(a[0]) + "|}"
    if k == "group":
        return "{:" + (v or "") + ": " + to_dsl(a[0]) + " :}"
    if k == "seq":
        return " ".join(to_dsl(x) for x in a)
    if k == "alt":
        return " / ".join(to_dsl(x) for x in a)
    if k == "rep":
        lo, hi = v
        inner = to_dsl(a[0])
        if lo == 0 and hi is None:
            return inner + "*"
        if lo == 1 and hi is None:
            return inner + "+"
        if lo == 0 and hi == 1:
            return inner + "?"
        if hi is None:
            return inner + f"^+{lo}" if lo != 1 else inner + "+"
        return inner + f"^{lo}" if hi == lo else inner + f"^-{hi}"
    if k == "node":
        return to_dsl(a[0])
    if k == "func":
        return to_dsl(a[0]) + "->" + v
    if k == "fold":
        return to_dsl(a[0]) + "~>" + v
    if k == "cmt":
        return to_dsl(a[0]) + "=>" + v
    if k == "eqback":
        return "=" + v
    if k == "back":
        return "=" + v
    if k == "set":
        items, comp = v
        body = "".join(_set_item(i) for i in items)
        return "[" + ("^" if comp else "") + body + "]"
    return f"<{k}>"


def _set_item(i):
    if isinstance(i, tuple):
        return str(i[0]) + "-" + str(i[1])
    return str(i)


def lift_grammar(rules: dict) -> dict[str, IR]:
    """Whole compiled rule table -> IR per rule."""
    return {name: lift(p) for name, p in rules.items()
            if isinstance(p, peg.Patt) and not name.startswith("\0")}
