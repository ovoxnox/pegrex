"""
smt 

║  Self-contained solver for the path-constraint fragment (QF_LIA-ish): 
║  learn(atoms) -> model; entails(model, guard); feasible(model). 
║  Swap in z3 behind the Backend protocol when guards outgrow the fragment."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

_ATOM = re.compile(r"^\((?P<var>[A-Za-z_]\w*)\s*(?P<op><=|>=|<|>|=)\s*(?P<k>-?\d+)\)$")
_NEG = re.compile(r"^\(not\s+\((?P<var>[A-Za-z_]\w*)\s*(?P<op><=|>=|<|>|=)\s*(?P<k>-?\d+)\)\)$")
_NEGATE = {"=": "!=", "<": ">=", "<=": ">", ">": "<=", ">=": "<"}


def _parse_atom(s: str):
    s = s.strip()
    if (m := _NEG.match(s)):
        return (_NEGATE[m.group("op")], m.group("var"), int(m.group("k")))
    if (m := _ATOM.match(s)):
        return (m.group("op"), m.group("var"), int(m.group("k")))
    return None


@dataclass
class Model:
    """Bounds model: var -> [lo, lo_inc, hi, hi_inc, neq]."""
    bounds: dict = field(default_factory=dict)

    def _entry(self, var: str):
        return self.bounds.setdefault(var, [None, True, None, True, set()])

    def add_atom(self, op: str, var: str, k: int) -> None:
        """add atom(op, var, k): see module docstring."""
        e = self._entry(var)
        if op == "=":
            e[0], e[1], e[2], e[3] = k, True, k, True
        elif op == "!=":
            e[4].add(k)
        elif op in ("<", "<="):
            inc = op == "<="
            if e[2] is None or k < e[2] or (k == e[2] and e[3] and not inc):
                e[2], e[3] = k, inc
        else:  # >, >=
            inc = op == ">="
            if e[0] is None or k > e[0] or (k == e[0] and e[1] and not inc):
                e[0], e[1] = k, inc

    def feasible(self) -> bool:
        """Implement feasible with the module's explicit API and failure semantics."""
        for lo, li, hi, hi_inc, neq in self.bounds.values():
            if lo is not None and hi is not None:
                if lo > hi or (lo == hi and not (li and hi_inc)):
                    return False
                if lo == hi and lo in neq:
                    return False
        return True


def learn(atoms) -> Model:
    """Implement learn with the module's explicit API and failure semantics."""
    m = Model()
    for a in atoms:
        if (p := _parse_atom(str(a))):
            m.add_atom(*p)
    return m


def _entails_atom(m: Model, op: str, var: str, k: int) -> bool:
    lo, li, hi, hi_inc, neq = m.bounds.get(var, [None, True, None, True, set()])
    match op:
        case "=":
            return (lo is not None and hi is not None and lo == hi == k
                    and li and hi_inc and k not in neq)
        case "!=":
            if lo is not None and hi is not None and lo == hi:
                return lo != k or k in neq
            if lo is not None and (k < lo or (k == lo and not li)):
                return True
            if hi is not None and (k > hi or (k == hi and not hi_inc)):
                return True
            return False
        case "<":
            return hi is not None and (hi < k or (hi == k and not hi_inc))
        case "<=":
            return hi is not None and (hi < k or (hi == k and hi_inc))
        case ">":
            return lo is not None and (lo > k or (lo == k and not li))
        case ">=":
            return lo is not None and (lo > k or (lo == k and li))
    return False


def _split_top(s: str) -> list[str]:
    parts, depth, cur = [], 0, ""
    for ch in s:
        depth += (ch == "(") - (ch == ")")
        if ch == " " and depth == 0:
            if cur:
                parts.append(cur)
                cur = ""
        else:
            cur += ch
    return parts + ([cur] if cur else [])


def entails(model: Model, guard) -> bool:
    """True if every model of the learned atoms satisfies the guard."""
    s = str(guard).strip()
    if s.startswith("(and"):
        return all(entails(model, p) for p in _split_top(s[4:-1]))
    if s.startswith("(or"):
        return any(entails(model, p) for p in _split_top(s[3:-1]))
    if s.startswith("(not"):
        inner = s[4:-1].strip()
        if (p := _parse_atom(inner)) and p[0] in ("<", "<=", ">", ">="):
            return _entails_atom(model, _NEGATE[p[0]], p[1], p[2])
        if p and p[0] == "=":
            return _entails_atom(model, "!=", p[1], p[2])
        return False
    return _entails_atom(model, *_parse_atom(s)) if _parse_atom(s) else False


# ── backend seam
class Backend:
    """The only surface specgen/idioms consume. Swap in z3 by subclassing."""

    def learn(self, atoms):
        """Implement learn with the module's explicit API and failure semantics."""
        return learn(atoms)

    def entails(self, model, guard):
        """Implement entails with the module's explicit API and failure semantics."""
        return entails(model, guard)

    def feasible(self, model):
        """Implement feasible with the module's explicit API and failure semantics."""
        return model.feasible()


_default = Backend()


def get_backend() -> Backend:
    """Implement get backend with the module's explicit API and failure semantics."""
    return _default


def set_backend(backend: Backend) -> None:
    """Implement set backend with the module's explicit API and failure semantics."""
    global _default
    _default = backend




# ── auto-escalation: fragment detection + optional z3
def _fragment_exceeded(atoms) -> bool:
    """True if atoms leave the single-variable linear fragment
    (multi-variable atoms or non-constant right-hand sides)."""
    import re as _re
    for a in map(str, atoms):
        vars_ = set(_re.findall(r"[A-Za-z_]\w*(?=@|\b)", a))
        vars_ = {v for v in vars_ if not v.isdigit()
                 and v not in ("not", "and", "or")}
        nums = _re.findall(r"-?\d+", a)
        if len(vars_) > 1 or (vars_ and not nums):
            return True
    return False


def auto_feasible(atoms) -> bool | None:
    """Return True/False, or None when no installed backend can decide.

    The bounds engine handles its exact single-variable fragment. Larger
    linear atoms go to Z3; a missing solver or an incomplete translation is
    UNKNOWN, never a best-effort answer with unsupported atoms discarded.
    """
    atoms = list(atoms)
    if not _fragment_exceeded(atoms):
        if any(_parse_atom(str(a)) is None for a in atoms):
            return None
        return learn(atoms).feasible()
    try:
        import z3
    except ImportError:
        return None
    try:
        solver = z3.Solver()
        for atom in atoms:
            solver.add(_to_z3(z3, str(atom)))
        verdict = solver.check()
    except (ValueError, TypeError, z3.Z3Exception):
        return None
    if verdict == z3.sat:
        return True
    if verdict == z3.unsat:
        return False
    return None


def _to_z3(z3, s):
    s = s.strip()
    m = _ATOM.match(s)
    if m:
        ops = {"=": lambda a, b: a == b, "!=": lambda a, b: a != b,
               "<": lambda a, b: a < b, "<=": lambda a, b: a <= b,
               ">": lambda a, b: a > b, ">=": lambda a, b: a >= b}
        return ops[m.group("op")](z3.Int(m.group("var")),
                                  int(m.group("k")))
    if (m := _NEG.match(s)):
        inner = f"({m.group('var')} {m.group('op')} {m.group('k')})"
        return z3.Not(_to_z3(z3, inner))
    simple = re.match(r"^\(\s*([A-Za-z_]\w*|-?\d+)\s*(<=|>=|<|>|=|!=)\s*"
                      r"([A-Za-z_]\w*|-?\d+)\s*\)$", s)
    if simple:
        def operand(text):
            """Implement operand with the module's explicit API and failure semantics."""
            return z3.IntVal(int(text)) if text.lstrip("-").isdigit() else z3.Int(text)
        left, right = operand(simple.group(1)), operand(simple.group(3))
        ops = {"=": lambda a, b: a == b, "!=": lambda a, b: a != b,
               "<": lambda a, b: a < b, "<=": lambda a, b: a <= b,
               ">": lambda a, b: a > b, ">=": lambda a, b: a >= b}
        return ops[simple.group(2)](left, right)
    # Multi-variable linear atoms use the same parser as the FM backend.
    # Variables remain integers; rational coefficients/bounds are exact.
    from .linsolve import LinearError, parse_atom
    try:
        atom = parse_atom(s)
    except LinearError as exc:
        raise ValueError(f"cannot translate: {s!r}") from exc
    def exact(value):
        # Z3 5.x removed RationalVal from the Python API. Integer numerator
        # and denominator division preserves the exact rational semantics on
        # both older and newer supported releases.
        """Implement exact with the module's explicit API and failure semantics."""
        numerator = z3.IntVal(value.numerator)
        if value.denominator == 1:
            return numerator
        # IntVal / IntVal is integer division in Z3 5.x; explicitly use a
        # real numerator so 1/2 cannot silently collapse to zero.
        return z3.RealVal(value.numerator) / value.denominator

    expr = sum((z3.Int(var) * exact(coeff)
                for var, coeff in atom.coeffs), z3.IntVal(0))
    bound = exact(atom.k)
    ops = {"=": lambda a, b: a == b, "!=": lambda a, b: a != b,
           "<": lambda a, b: a < b, "<=": lambda a, b: a <= b,
           ">": lambda a, b: a > b, ">=": lambda a, b: a >= b}
    return ops[atom.op](expr, bound)


# ── cross-check: bounds backend vs z3 on the same queries
class SMTCrosscheckError(ValueError):
    """Refusal: the cross-check itself cannot be performed honestly."""


def _z3():
    try:
        import z3
        return z3
    except ImportError as e:
        raise SMTCrosscheckError(
            "z3 not installed; refusing to cross-check silently "
            "(pip install z3-solver)") from e


def _guard_to_z3(z3, s):
    """Guard syntax: atom | (not atom) | (and ...) | (or ...)."""
    s = s.strip()
    if s.startswith("(and"):
        return z3.And(*[_guard_to_z3(z3, p) for p in _split_top(s[4:-1])])
    if s.startswith("(or"):
        return z3.Or(*[_guard_to_z3(z3, p) for p in _split_top(s[3:-1])])
    if s.startswith("(not"):
        return z3.Not(_guard_to_z3(z3, s[4:-1].strip()))
    return _to_z3(z3, s)


def _z3_entails(z3, atoms, guard) -> bool:
    solver = z3.Solver()
    for a in atoms:
        solver.add(_to_z3(z3, a))
    solver.add(z3.Not(_guard_to_z3(z3, guard)))
    return solver.check() == z3.unsat


def _z3_feasible(z3, atoms) -> bool:
    solver = z3.Solver()
    for a in atoms:
        solver.add(_to_z3(z3, a))
    return solver.check() == z3.sat


def _gen_guards(atoms, n, seed):
    """Deterministic single-literal guards from the atoms' vars/constants."""
    import random
    parsed = [_parse_atom(a) for a in atoms]
    vars_ = sorted({p[1] for p in parsed})
    consts = sorted({p[2] for p in parsed})
    ks = sorted({c + d for c in consts for d in (-1, 0, 1)} | {0})
    cands = [f"({v} {op} {k})" for v in vars_
             for op in ("<", "<=", "=", ">=", ">") for k in ks]
    cands += [f"(not {c})" for c in list(cands)]
    rng = random.Random(seed)
    rng.shuffle(cands)
    return cands[:n]


def crosscheck(atoms, guards=None, n=32, seed=0) -> dict:
    """Check the active backend's learn/entails verdicts against z3 on the
    same atom set.  Never returns a silent verdict:
      - z3 missing            -> {"agree": None, "refusal": ...}
      - atom out of fragment  -> {"agree": None, "refusal": ...} (the backend
        silently ignores unparseable atoms; a cross-check that pretended to
        vouch for them would be a lie)
      - any disagreement      -> {"agree": False, "witnesses": [...]}"""
    atoms = [str(a) for a in atoms]
    bad = [a for a in atoms if _parse_atom(a) is None]
    if bad:
        return {"agree": None, "queries": 0,
                "refusal": f"atom outside cross-check fragment: {bad[0]!r}"}
    try:
        z3 = _z3()
    except SMTCrosscheckError as e:
        return {"agree": None, "queries": 0, "refusal": str(e)}
    backend = get_backend()
    model = backend.learn(atoms)
    if guards is None:
        guards = _gen_guards(atoms, n, seed)
    witnesses = []
    for g in guards:
        b = backend.entails(model, g)
        z = _z3_entails(z3, atoms, g)
        if b != z:
            witnesses.append({"guard": g, "backend": b, "z3": z})
    bf, zf = backend.feasible(model), _z3_feasible(z3, atoms)
    if bf != zf:
        witnesses.append({"guard": "<feasibility>", "backend": bf, "z3": zf})
    return {"queries": len(guards) + 1, "agree": not witnesses,
            "witnesses": witnesses, "refusal": None}
