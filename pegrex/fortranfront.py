"""
fortranfront - native Fortran frontend

Free-form Fortran function units in the certified subset:
    function name(args) ... end function
    x = expr                       (assignment; assignment to the FUNCTION
                                    NAME is the result expression)
    if (cond) then / else / end if
    COMMON /blk/ a, b   (or blank: COMMON a, b)  -- shared block declarations,
                                    seedable via contracts(src, common=...)
Operators translated: .GT. .GE. .LT. .LE. .EQ. .NE. .AND. .OR. and /=.
do-loops, one-line IFs, and program units refuse loudly."""

from __future__ import annotations

import re
from fractions import Fraction

from .legacy_common import atoms_of_cond, negate_atoms
from .ir import parse_expr, to_sym
from .sym import Op, V


class FortranError(ValueError):
    """Outside the certified Fortran fragment -- loud refusal."""


_FN_RX = re.compile(r"^\s*(?:\w+\s+)?function\s+(\w+)\s*\(([^)]*)\)", re.I)
_END_RX = re.compile(r"^\s*end\s+function", re.I)
_IF_RX = re.compile(r"^\s*if\s*\((.+)\)\s*then\s*$", re.I)
_ELSE_RX = re.compile(r"^\s*else\s*$", re.I)
_ENDIF_RX = re.compile(r"^\s*end\s*if\s*$", re.I)
_ASSIGN_RX = re.compile(r"^\s*(\w+)\s*=\s*(.+)$")
_COMMON_RX = re.compile(r"^\s*common\s*(?:/\s*(\w*)\s*/)?\s*([^=!]+)$", re.I)
_DATA_RX = re.compile(r"^\s*data\s+(\w+)\s*/\s*([^/]+?)\s*/", re.I)


def _tr(text):
    t = text
    for a, b in [(r"\.GT\.", ">"), (r"\.GE\.", ">="), (r"\.LT\.", "<"),
                 (r"\.LE\.", "<="), (r"\.EQ\.", "=="), (r"\.NE\.", "!="),
                 (r"\.AND\.", "and"), (r"\.OR\.", "or")]:
        t = re.sub(a, b, t, flags=re.I)
    t = t.replace("/=", "!=")
    return t


def _parse(lines, name):
    stmts = []
    i = 0
    while i < len(lines):
        raw = lines[i]
        s = raw.strip()
        if not s or s.startswith("!"):
            i += 1
            continue
        if _END_RX.match(raw) or re.match(r"^\s*contains\b", raw, re.I):
            break
        if re.match(r"^\s*(program|module|subroutine)\b", raw, re.I):
            raise FortranError(f"fortran: only function units are certified: {s!r}")
        if re.match(r"^\s*do\b", raw, re.I):
            raise FortranError(f"fortran: do-loops refuse loudly: {s!r}")
        if re.match(r"^\s*if\s*\(.+\)\s+\S", raw) and not s.lower().endswith("then"):
            raise FortranError(f"fortran: one-line IF is outside the fragment: {s!r}")
        m = _IF_RX.match(raw)
        if m:
            base = i + 1
            body, r1 = _parse(lines[base:], name)
            else_at = base + r1
            orelse = []
            if else_at < len(lines) and _ELSE_RX.match(lines[else_at]):
                orelse, r2 = _parse(lines[else_at + 1:], name)
                end_at = else_at + 1 + r2
            else:
                end_at = else_at
            if end_at >= len(lines) or not _ENDIF_RX.match(lines[end_at]):
                raise FortranError(f"fortran: missing END IF near {s!r}")
            stmts.append(("if", _tr(m.group(1)), body, orelse))
            i = end_at + 1
            continue
        if _ELSE_RX.match(raw) or _ENDIF_RX.match(raw):
            return stmts, i
        m = _COMMON_RX.match(raw)
        if m:
            block = (m.group(1) or "").upper()
            vars_ = [v.strip().lower() for v in m.group(2).split(",")
                     if v.strip()]
            if not vars_:
                raise FortranError(f"fortran: COMMON with no variables: "
                                   f"{s!r}")
            stmts.append(("common", block, vars_))
            i += 1
            continue
        m = _ASSIGN_RX.match(raw)
        if m:
            stmts.append(("assign", m.group(1).lower(), m.group(2).strip()))
            i += 1
            continue
        raise FortranError(f"fortran: unsupported statement {s!r}")
    return stmts, i


def _sym_of(val):
    if isinstance(val, str):
        return to_sym(parse_expr(_tr(val)))
    return val


def collect_commons(sources: list) -> dict:
    """Union common declarations across program units: {block: {var:
    value|None}}. Initial values come from DATA statements; conflicting
    initial values for the same block/var refuse loudly (named). Units
    without common contribute nothing -- never an error."""
    out = {}
    for src in sources:
        decls = {}
        inits = {}
        for line in src.splitlines():
            m = _COMMON_RX.match(line)
            if m:
                block = (m.group(1) or "").upper()
                vars_ = [v.strip().lower() for v in m.group(2).split(",")
                         if v.strip()]
                decls.setdefault(block, []).extend(vars_)
                continue
            d = _DATA_RX.match(line)
            if d:
                tok = d.group(2).split(",")[0].strip()
                try:
                    inits[d.group(1).lower()] = Fraction(tok)
                except (ValueError, ZeroDivisionError):
                    raise FortranError(f"fortran: unsupported DATA initial "
                                       f"value {tok!r}")
        for block, vars_ in decls.items():
            b = out.setdefault(block, {})
            for v in vars_:
                b.setdefault(v, None)
                if v in inits:
                    val = inits[v]
                    if b[v] is not None and b[v] != val:
                        raise FortranError(
                            f"fortran: conflicting common initial values "
                            f"for /{block or 'BLANK'}/ {v}: {b[v]} vs {val}")
                    b[v] = val
    return out


def contracts(src, common=None):
    """[(frozenset(guard-atoms), result-expr)] for a function unit.

    common: optional {block: {var: value}} seeding the variable
    environment (from collect_commons across program units). common
    declarations are recorded but carry no semantics of their own here;
    only the caller-provided seed bounds the shared values -- nothing is
    invented."""
    lines = src.splitlines()
    name = None
    start = 0
    for i, l in enumerate(lines):
        m = _FN_RX.match(l)
        if m:
            name = m.group(1).lower()
            start = i + 1
            break
    if not name:
        if re.search(r"^\s*(program|module|subroutine)\b", src, re.I | re.M):
            raise FortranError("fortran: only function units are certified")
        raise FortranError("fortran: no function unit found")
    stmts, _ = _parse(lines[start:], name)
    env0 = {}
    for block, vars_ in (common or {}).items():
        for var, val in vars_.items():
            if val is None:
                continue  # declared but uninitialized: symbolic
            env0[var.lower()] = _sym_of(val)
    out = []

    def walk(ss, env, guards):
        """walk(ss, env, guards): see module docstring."""
        for st in ss:
            if st[0] == "if":
                walk(st[2], dict(env), guards + atoms_of_cond(st[1]))
                walk(st[3], dict(env), guards + negate_atoms(st[1]))
                return
            if st[0] == "common":
                continue  # declaration only; semantics via common=
            dst, expr = st[1], st[2]
            e = to_sym(parse_expr(_tr(expr)))
            e = _resolve(e, env)
            env[dst] = e
        if name not in env:
            raise FortranError(f"fortran: function name {name} never assigned "
                               f"(Fortran result convention)")
        out.append((frozenset(guards), str(env[name])))

    walk(stmts, dict(env0), [])
    # canonical form for the native legacy frontends: UPPERCASE identifiers,
    # so COBOL N and Fortran n denote the same item in contract space
    def up(s):
        """up(s): see module docstring."""
        return re.sub(r"[A-Za-z_]\w*", lambda m: m.group(0).upper(), s)
    return [(frozenset(up(a) for a in cs), up(res)) for cs, res in out]


def _resolve(e, env):
    from .sym import Sym
    if isinstance(e, Sym) and e.name.lower() in env:
        return env[e.name.lower()]
    if isinstance(e, Op):
        return Op(e.op, tuple(_resolve(a, env) for a in e.args))
    return e
