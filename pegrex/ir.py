"""
ir — typed expression IR (pegrex-IR, foundation slice)  

║  A real expression language replacing regex-parsed conditions.           
║  Tokenizer + Pratt parser: arithmetic (+ - * / %), comparisons, calls,   
║  field access, unary minus, and/or. Lowers to sym.py trees; linear       
║  fragments lower further to solver atoms (see linsolve).                 
║  Contract: anything unparseable is a LOUD CondError -- never a silent    
║  mis-parse. That refusal is the negative control of certificate"""

from __future__ import annotations

from dataclasses import dataclass
from fractions import Fraction

from .sym import (And, Eq, Ge, Gt, Le, Lt, Not, Op, Or, V, const)


class CondError(ValueError):
    """Unparseable condition -- raised loudly instead of regex-guessing."""


# ---------------------------------------------------------------------------
# Typed IR nodes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Expr:
    """One node. `ty` is the static type name ('int','bool','unknown',...)."""
    kind: str             # var | const | bin | cmp | call | field | not | bool
    ty: str
    value: object = None  # const literal, var name, op, ...
    args: tuple = ()

    def __str__(self) -> str:
        """  str  (): see module docstring."""
        k = self.kind
        if k == "var":
            return str(self.value)
        if k == "const":
            return repr(self.value)
        if k == "not":
            return f"(not {self.args[0]})"
        if k == "bool":
            sep = f" {self.value} "
            return "(" + sep.join(str(a) for a in self.args) + ")"
        if k in ("bin", "cmp"):
            return "(" + f" {self.value} ".join(str(a) for a in self.args) + ")"
        if k == "call":
            return f"{self.value}(" + ", ".join(str(a) for a in self.args) + ")"
        if k == "field":
            return f"{self.args[0]}.{self.value}"
        return f"<{k}>"


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_TOK = [
    ("num",   __import__("re").compile(r"\d+(?:\.\d+)?")),
    ("id",    __import__("re").compile(r"[A-Za-z_]\w*")),
    ("op",    __import__("re").compile(r"<=|>=|==|!=|=|&&|\|\||[+\-*/%<>&|]")),
    ("punct", __import__("re").compile(r"[(),.()]")),
    ("ws",    __import__("re").compile(r"\s+")),
]
_TY_CONST = {"true": ("bool", True), "false": ("bool", False)}


def tokenize(text: str):
    """tokenize(text): see module docstring."""
    import re
    toks, i, n = [], 0, len(text)
    while i < n:
        for kind, rx in _TOK:
            m = rx.match(text, i)
            if m:
                if kind != "ws":
                    toks.append((kind, m.group(0)))
                i = m.end()
                break
        else:
            raise CondError(f"ir: cannot tokenize at {text[i:]!r} (pos {i})")
    return toks


# ---------------------------------------------------------------------------
# Pratt parser
# ---------------------------------------------------------------------------

_CMP_OPS  = {"<": Lt, "<=": Le, ">": Gt, ">=": Ge, "==": Eq, "=": Eq,
           "!=": lambda a, b: Not(Eq(a, b))}
_BIN_TY   = {"+": "int", "-": "int", "*": "int", "/": "unknown", "%": "int"}
_PREC     = {"||": 1, "&&": 2, "==": 3, "!=": 3, "=": 3, "<": 4, "<=": 4, ">": 4, ">=": 4,
             "+": 5, "-": 5, "*": 6, "/": 6, "%": 6}
_RIGHT    = set()


def parse_expr(text: str) -> Expr:
    toks = tokenize(text)
    pos = [0]

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else (None, None)

    def next_():
        if pos[0] >= len(toks):
            raise CondError("ir: unexpected end of condition")
        t = toks[pos[0]]
        pos[0] += 1
        return t

    def expect(kind, val=None):
        k, v = next_()
        if k != kind or (val is not None and v != val):
            raise CondError(f"ir: expected {val or kind}, got {v!r}")
        return v

    def primary():
        kind, val = next_()
        if kind == "id" and val == "not":
            return Expr("not", "bool", None, (expr(4),))
        if kind == "id" and val in ("and", "or"):
            raise CondError(f"ir: misplaced {val!r}")
        if kind == "num":
            return Expr("const", "int", Fraction(val) if "." in val else int(val))
        if kind == "id":
            if val in _TY_CONST:
                ty, lit = _TY_CONST[val]
                return Expr("const", ty, lit)
            e = Expr("var", "int", val)
            # call or field chain
            while True:
                k, v = peek()
                if (k, v) == ("punct", "("):
                    next_()
                    args = []
                    if peek() != ("punct", ")"):
                        args.append(expr(0))
                        while peek() == ("punct", ","):
                            next_()
                            args.append(expr(0))
                    expect("punct", ")")
                    e = Expr("call", "unknown", val, tuple(args))
                elif (k, v) == ("punct", "."):
                    next_()
                    fk, fv = next_()
                    if fk != "id":
                        raise CondError("ir: field name expected after '.'")
                    e = Expr("field", "unknown", fv, (e,))
                else:
                    break
            return e
        if (kind, val) == ("punct", "("):
            e = expr(0)
            expect("punct", ")")
            return e
        if (kind, val) == ("op", "-"):
            z = primary()
            if z.kind == "const" and z.ty == "int":
                return Expr("const", "int", -z.value)
            return Expr("bin", "int", "-", (Expr("const", "int", 0), z))
        if kind == "id" or (kind, val) == ("punct", ")"):
            raise CondError(f"ir: unexpected {val!r}")
        raise CondError(f"ir: unexpected token {val!r}")

    def expr(min_prec):
        left = primary()
        while True:
            k, v = peek()
            if k == "id" and v in ("and", "or"):
                v = "&&" if v == "and" else "||"
                k = "op"
            if k != "op" or v not in _PREC or _PREC[v] < min_prec:
                break
            next_()
            rhs = expr(_PREC[v] + (0 if v in _RIGHT else 1))
            if v in _CMP_OPS:
                left = Expr("cmp", "bool", v, (left, rhs))
            elif v in ("&&", "||"):
                left = Expr("bool", "bool", v, (left, rhs))
            else:
                left = Expr("bin", _BIN_TY[v], v, (left, rhs))
        return left

    e = expr(0)
    if pos[0] != len(toks):
        raise CondError(f"ir: trailing tokens in {text!r}")
    return e


def parse_condition(text: str) -> Expr:
    """Parse a full condition. Result kind is cmp/bool/not; anything else is
    not a condition -> CondError."""
    e = parse_expr(text)
    if e.kind not in ("cmp", "bool", "not"):
        raise CondError(f"ir: {text!r} is not a condition")
    return e


# ---------------------------------------------------------------------------
# Lowering: IR -> sym.py formula trees
# ---------------------------------------------------------------------------

def to_sym(e: Expr):
    """IR -> sym tree. Calls/fields become opaque Sym atoms (typed unknown)."""
    if e.kind == "var":
        return V(str(e.value))
    if e.kind == "const":
        return const(e.value) if e.ty == "bool" else e.value
    if e.kind == "bin":
        from .sym import Op as _Op
        return _Op(str(e.value), tuple(to_sym(a) for a in e.args))
    if e.kind == "cmp":
        return _CMP_OPS[str(e.value)](to_sym(e.args[0]), to_sym(e.args[1]))
    if e.kind == "bool":
        comb = And if e.value == "&&" else Or
        return comb(*[to_sym(a) for a in e.args])
    if e.kind == "not":
        return Not(to_sym(e.args[0]))
    if e.kind == "call":
        return V(str(e.value) + "(" + ", ".join(str(to_sym(a)) for a in e.args) + ")")
    if e.kind == "field":
        return V(str(to_sym(e.args[0])) + "." + str(e.value))
    raise CondError(f"ir: no lowering for kind {e.kind}")


def linearize(e) -> tuple[dict, Fraction] | None:
    """Returns (coeffs, const) if `e` is linear in vars, else None."""
    from .sym import Op, Sym
    if isinstance(e, Sym):
        name = e.name
        if name in ("true", "false") or "(" in name or "." in name:
            return None   # opaque atom: call/field -- not linear
        return ({name: Fraction(1)}, Fraction(0))
    if isinstance(e, (int, Fraction)) and not isinstance(e, bool):
        return ({}, Fraction(e))
    if isinstance(e, Op):
        if e.op in ("+", "-"):
            l = linearize(e.args[0]); r = linearize(e.args[1])
            if l is None or r is None:
                return None
            c = dict(l[0])
            for k, v in r[0].items():
                c[k] = c.get(k, Fraction(0)) + (v if e.op == "+" else -v)
            k0 = l[1] + (r[1] if e.op == "+" else -r[1])
            return (c, k0)
        if e.op == "*":
            l = linearize(e.args[0]); r = linearize(e.args[1])
            if l is None or r is None:
                return None
            if not l[0]:         # const * r
                return ({k: l[1] * v for k, v in r[0].items()}, l[1] * r[1])
            if not r[0]:                       # l * const
                return ({k: v * r[1] for k, v in l[0].items()}, l[1] * r[1])
            return None          # var * var: nonlinear
    return None


_ATOM_TXT = {"<": "<", "<=": "<=", ">": ">", ">=": ">=", "=": "=", "!=": "!="}


_FLIP = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "=": "!=", "!=": "="}


def cond_to_atom(cond) -> str:
    """sym comparison -> solver atom text. Linear fragment normalizes to
    `(c1*v1 + ... ⋚ k)`; anything else is returned as an opaque atom and the
    solver treats it as an uninterpreted boolean (feasible, never entailed).
    Negated comparisons FLIP (integer semantics): not(a<b) === a>=b."""
    from .sym import Op
    if isinstance(cond, Op) and cond.op == "not" and len(cond.args) == 1:
        inner = cond.args[0]
        if isinstance(inner, Op) and inner.op in _FLIP and len(inner.args) == 2:
            return cond_to_atom(Op(_FLIP[inner.op], inner.args))
    if isinstance(cond, Op) and cond.op in _ATOM_TXT and len(cond.args) == 2:
        lin = None
        try:
            a = linearize(cond.args[0]); b = linearize(cond.args[1])
            if a is not None and b is not None:
                c = dict(a[0])
                for k, v in b[0].items():
                    c[k] = c.get(k, Fraction(0)) - v
                lin = (c, b[1] - a[1])
        except Exception:
            lin = None
        if lin is not None and lin[0]:
            terms = []
            for var in sorted(lin[0]):
                cf = lin[0][var]
                if cf == 0:
                    continue
                # ALWAYS explicit: "-1*x", never bare "-x"
                terms.append(f"{cf}*{var}")
            if not terms:
                k = lin[1]
                op = cond.op
                ok = {"<": k > 0, "<=": k >= 0, ">": k < 0, ">=": k <= 0,
                      "=": k == 0, "!=": k != 0}[op]
                return "(true)" if ok else "(false)"
            lhs = " + ".join(terms).replace("+ -", "- ")
            return f"({lhs} {_ATOM_TXT[cond.op]} {lin[1]})"
        if lin is not None and not lin[0]:
            k = lin[1]
            ok = {"<": k > 0, "<=": k >= 0, ">": k < 0, ">=": k <= 0,
                  "=": k == 0, "!=": k != 0}[cond.op]
            return "(true)" if ok else "(false)"
        return f"({cond})"  # opaque atom (calls/fields)
    return f"({cond})"


# Drop-in condition lowerer (replaces make_cond's regex atom path)

_REGEX_OK = __import__("re").compile(
    r"^\s*\(?\s*([A-Za-z_]\w*)\s*(<=|>=|<|>|==|!=)\s*(-?\d+|[A-Za-z_]\w*)\s*\)?\s*$")


def lower_condition(text: str):
    """condition text -> sym formula.

    Order: (1) regex fast path for the old single-var fragment (identical
    results, zero risk); (2) IR parser for everything else -- `a+1 < b`,
    calls, field access, compound and/or; (3) anything unparseable raises
    CondError. The old make_cond *silently mis-parsed* step-2 cases; this 
    seam refuses them loudly instead."""
    t = text.strip()
    if t.startswith("(") and t.endswith(")"):
        t2 = t[1:-1].strip()
    else:
        t2 = t
    m = _REGEX_OK.match(t2)
    if m:
        a, b = m.group(1), m.group(3)
        av = V(a) if not a.lstrip("-").isdigit() else const(int(a))
        bv = V(b) if not b.lstrip("-").isdigit() else const(int(b))
        return _CMP_OPS[m.group(2)](av, bv)
    try:
        return to_sym(parse_condition(t))
    except CondError:
        pass
    e = parse_condition(t2)
    return to_sym(e)


def lower_condition_node(node, src: str):
    """lower_condition over a CFG condition node (tree-sitter slice or child)."""
    txt = node.children[0] if getattr(node, "children", None) and         isinstance(node.children[0], str) else src[node.pos:node.endpos]
    return lower_condition(txt)
