"""
linsolve — multi-variable linear arithmetic (Fourier-Motzkin)    

║  QF_LIA fragment solver behind the existing smt.Backend protocol.        
║  Integer semantics (matching smt.py): strict < becomes <= k-1.           
║  "=" is a pair of opposing inequalities; != is a disequality.            
║  learn -> LinearModel; feasibility via FM elimination over rationals,    
║  plus a per-variable integer-window-emptiness probe (sound but not a     
║  complete integer decision procedure -- see _eliminate)"""

from __future__ import annotations

import math
import re
import time
from dataclasses import dataclass, field
from fractions import Fraction
from functools import lru_cache

from .ir import cond_to_atom
from .smt import Backend

_ATOM_RX = re.compile(
    r"^\(?\s*(?P<lhs>-?[\d/]+\*[A-Za-z_]\w*(?:\s*[+-]\s*(?:[\d/]+\*[A-Za-z_]\w*|[A-Za-z_]\w*))*"
    r"|[A-Za-z_]\w*(?:\s*[+-]\s*(?:[\d/]+\*[A-Za-z_]\w*|[A-Za-z_]\w*))*)"
    r"\s*(?P<op><=|>=|<|>|=|!=)\s*(?P<rhs>-?[\d/]+)\s*\)?$")
_TERM_RX = re.compile(r"(?P<cf>-?[\d/]+)\*(?P<var>[A-Za-z_]\w*)")
_BARE_RX = re.compile(r"(?<![\w/*])(?P<v>[A-Za-z_]\w*)(?!\*)")


class LinearError(ValueError):
    """Atom outside the linear fragment -- loud refusal, never a guess."""


@dataclass(frozen=True)
class LinAtom:
    coeffs: tuple   # sorted ((var, Fraction coeff), ...)
    op: str         # <= >= < > = !=  (raw)
    k: Fraction

    def cd(self) -> dict:
        """cd(): see module docstring."""
        return dict(self.coeffs)


def parse_atom(txt: str) -> LinAtom:
    """Parse solver atom text. Raises LinearError outside the fragment."""
    t = txt.strip()
    while t.startswith("(") and t.endswith(")"):
        t = t[1:-1].strip()
    m = _ATOM_RX.match(t)
    if not m:
        raise LinearError(f"linsolve: non-linear or malformed atom {txt!r}")
    coeffs: dict = {}
    lhs = m.group("lhs")
    # signed terms: [+-]?  (N* | N/ D* )? var   -- covers x, -x, 2*x, -2*x, "x - y"
    for tm in re.finditer(
            r"(?P<sign>[+-]?)\s*(?:(?P<cf>[\d/]+)\*)?(?P<v>[A-Za-z_]\w*)",
            lhs):
        c = Fraction(tm.group("cf") or 1)
        if tm.group("sign") == "-":
            c = -c
        coeffs[tm.group("v")] = coeffs.get(tm.group("v"), Fraction(0)) + c
    coeffs = {v: c for v, c in coeffs.items() if c != 0}
    return LinAtom(tuple(sorted(coeffs.items())), m.group("op"),
                   Fraction(m.group("rhs")))


def atoms_of(formula) -> list:
    """sym formula -> flat atom-text list (top-level And split)."""
    from .sym import Op
    out = []
    if isinstance(formula, Op) and formula.op == "and":
        for a in formula.args:
            out.extend(atoms_of(a))
        return out
    return [cond_to_atom(formula)]


# ---------------------------------------------------------------------------
# Integer normalization: everything becomes  body <= k  (+ != side-list)
# ---------------------------------------------------------------------------

def _normalize(a: LinAtom) -> list:
    """Normalize QF_LIA atoms; reject rationals outside the integer model.

    FM arithmetic is rational internally, but strict-inequality slack and
    model reconstruction are integer-specific. Accepting fractional input
    here would silently change its meaning, so callers get a loud refusal.
    """
    if a.k.denominator != 1 or any(c.denominator != 1 for _, c in a.coeffs):
        raise LinearError("linsolve: fractional atom outside the QF_LIA integer fragment")
    if a.op == "<":
        return [LinAtom(a.coeffs, "<=", a.k - 1)]
    if a.op == ">":
        return [LinAtom(tuple(sorted((v, -c) for v, c in a.coeffs)),
                        "<=", -(a.k + 1))]   # x>k === -x<=-k-1 (integer slack)
    if a.op == ">=":
        return [LinAtom(tuple(sorted((v, -c) for v, c in a.coeffs)), "<=", -a.k)]
    if a.op == "=":
        return [LinAtom(a.coeffs, "<=", a.k),
                LinAtom(tuple(sorted((v, -c) for v, c in a.coeffs)), "<=", -a.k)]
    return [a]


def _negate_norm(a: LinAtom) -> list:
    """Negation of an already-normalized atom (<=, !=)."""
    if a.op == "<=":
        return [LinAtom(tuple(sorted((v, -c) for v, c in a.coeffs)),
                        "<=", -(a.k + 1))]     # x>k === -x<=-k-1 (integer slack)
    if a.op == "!=":
        return [LinAtom(a.coeffs, "<=", a.k),
                LinAtom(tuple(sorted((v, -c) for v, c in a.coeffs)), "<=", -a.k)]
    raise LinearError(f"linsolve: cannot negate {a.op}")


def _txt(a: LinAtom) -> str:
    terms = []
    for v, c in a.coeffs:
        terms.append(f"{c}*{v}")   # always explicit: parse_atom can't read bare "-x"
    lhs = " + ".join(terms).replace("+ -", "- ") if terms else "0"
    return f"({lhs} {a.op} {a.k})"


# -------------------------
# Fourier-Motzkin
# -------------------------

def _unit_bounds(ineqs, var):
    """Split constraints on `var` into unit-normalized high/low bounds.
    high: (rest, k) means  x + rest <= k.   low:  -x + rest <= k."""
    highs, lows, others = [], [], []
    for coeffs, k in ineqs:
        c = coeffs.get(var, 0)
        if c == 0:
            others.append((coeffs, k))
        elif c > 0:
            rest = {v: cc / c for v, cc in coeffs.items() if v != var}
            highs.append((rest, k / c))
        else:
            rest = {v: cc / -c for v, cc in coeffs.items() if v != var}
            lows.append((rest, k / -c))
    return highs, lows, others


def _combine(hi, lo):
    """x + r_h <= k_h  AND  -x + r_l <= k_l   ==>   r_h + r_l <= k_h + k_l."""
    rest = dict(hi[0])
    for v, c in lo[0].items():
        rest[v] = rest.get(v, Fraction(0)) + c
    return ({v: c for v, c in rest.items() if c != 0}, hi[1] + lo[1])


@dataclass
class LinearModel:
    src: list = field(default_factory=list)       # normalized LinAtoms
    src_texts: list = field(default_factory=list)
    opaques: list = field(default_factory=list)
    neqs: list = field(default_factory=list)      # [(coeffs, k)]
    hist: dict = field(default_factory=dict)      # var -> (highs, lows) at elim step
    hi: dict = field(default_factory=dict)        # var -> [(rest, k)]  (original)
    lo: dict = field(default_factory=dict)
    vars: list = field(default_factory=list)
    feasible_flag: bool = True

    def feasible(self) -> bool:
        return self.feasible_flag

    def model(self) -> dict:
        """Concrete integer model via textbook FM reconstruction (reverse
        back-substitution over per-elimination-step bounds), with
        DISEQUALITY-AWARE value choice: a var's value skips values forbidden
        by any neq (given already-assigned vars). Final verification is the
        safety net; {} = honest 'no model found', never a wrong model."""
        if not self.feasible_flag:
            return {}
        assign: dict = {}
        for var in reversed(self.vars):
            highs, lows = self.hist.get(var, ([], []))
            lo_b = hi_b = None
            for rest, k in highs:                    # var + rest <= k
                b = k - sum(c * assign[v] for v, c in rest.items())
                hi_b = b if hi_b is None else min(hi_b, b)
            for rest, k in lows:                     # -var + rest <= k
                b = sum(c * assign[v] for v, c in rest.items()) - k
                lo_b = b if lo_b is None else max(lo_b, b)
            lo_i = math.ceil(lo_b) if lo_b is not None else -10**9
            hi_i = math.floor(hi_b) if hi_b is not None else 10**9

            def neq_ok(v, asn):
                for coeffs, k in self.neqs:
                    if var in coeffs:
                        total = sum(c * (asn[u] if u != var else v)
                                    for u, c in coeffs.items())
                        if total == k:
                            return False
                return True

            val = min(max(Fraction(0), lo_i), hi_i)
            if not neq_ok(val, assign):
                found = None
                for d in range(1, max(64, hi_i - lo_i + 1)):
                    for cand in (val + d, val - d):
                        if lo_i <= cand <= hi_i and neq_ok(cand, assign):
                            found = cand
                            break
                    if found is not None:
                        break
                if found is None:
                    return {}
                val = found
            assign[var] = val

        def ok_all(asn):
            for a in self.src:
                if a.op == "<=" and sum(c * asn.get(v, Fraction(0))
                                        for v, c in a.cd().items()) > a.k:
                    return False
            for c2, kk in self.neqs:
                if sum(c * asn.get(v, Fraction(0)) for v, c in c2.items()) == kk:
                    return False
            return True
        if not ok_all(assign):
            return {}
        return {v: int(x) for v, x in assign.items()}


def _eliminate(model: LinearModel) -> None:
    """Feasibility via FM over rationals; slack already integerized.
    Also fills model.hi/lo/var from the original normalized system."""
    ineqs = [(a.cd(), a.k) for a in model.src if a.op == "<="]
    model.neqs = [(a.cd(), a.k) for a in model.src if a.op == "!="]
    varset = sorted({v for coeffs, _ in ineqs for v in coeffs})
    model.vars = varset
    for var in varset:
        highs, lows, others = _unit_bounds(ineqs, var)
        model.hist[var] = (highs, lows)  # bounds in terms of later vars only
        new = list(others)
        for h in highs:
            for l in lows:
                new.append(_combine(h, l))
        for coeffs, k in new:  # constant contradiction?
            if not coeffs and k < 0:
                model.feasible_flag = False
                return
        ineqs = new
    for coeffs, k in ineqs:
        if not coeffs and k < 0:
            model.feasible_flag = False
            return
    for var in varset:
        highs, lows = model.hist[var]
        hi = None
        for rest, k in highs:
            if not rest: # direct bound: x <= k
                hi = k if hi is None else min(hi, k)
        lo = None
        for rest, k in lows:
            if not rest: # direct bound: -x <= k, i.e. x >= -k
                b = -k
                lo = b if lo is None else max(lo, b)
        if lo is not None and hi is not None and math.ceil(lo) > math.floor(hi):
            model.feasible_flag = False
            return


@lru_cache(maxsize=4096)
def _implication_probe_feasible(src_atoms: tuple, negated: LinAtom) -> bool:
    """Memoize one immutable constraints + negated-guard feasibility probe."""
    return _learn_atoms(list(src_atoms) + [negated]).feasible_flag


def _learn_atoms(src_atoms) -> "LinearModel":
    """Build a model directly from already-normalized LinAtom objects --
    skips text parsing entirely. entails()'s per-guard-piece probes always
    reuse the base model's already-parsed atoms (model.src) plus one
    already-built negated LinAtom (from _negate_norm); round-tripping both
    through text (_txt(...) then re-parsing via learn()) was pure waste,
    repeated once per guard atom checked -- this is the same elimination,
    just without re-deriving data that was already sitting in hand."""
    model = LinearModel()
    model.src = list(src_atoms)
    model.src_texts = [_txt(a) for a in model.src]
    _eliminate(model)
    return model


class LinearBackend(Backend):
    """Backend-protocol multi-variable linear engine with optional query budgets."""

    name = "fourier-motzkin"

    def __init__(self, *, max_queries: int | None = None,
                 timeout_ms: int | None = None) -> None:
        self.max_queries = max_queries
        self.timeout_ms = timeout_ms
        self.queries = 0
        self._deadline = (time.monotonic() + timeout_ms / 1000
                          if timeout_ms is not None else None)
        self.last_result = {"status": "unknown", "reason": "no query executed"}

    def _consume_query(self) -> str | None:
        self.queries += 1
        if self.max_queries is not None and self.queries > self.max_queries:
            return f"solver query budget {self.max_queries} exceeded"
        if self._deadline is not None and time.monotonic() > self._deadline:
            return f"solver deadline {self.timeout_ms}ms exceeded"
        return None

    def learn(self, atoms):
        model = LinearModel()
        for atom in atoms:
            txt = str(atom).strip()
            if txt in ("(true)", "true"):
                continue
            if txt in ("(false)", "false"):
                model.feasible_flag = False
                model.src, model.src_texts = [], []
                return model
            try:
                la = parse_atom(txt)
            except LinearError:
                model.opaques.append(txt)
                continue
            for n in _normalize(la):
                model.src.append(n)
                model.src_texts.append(_txt(n))
        if model.feasible_flag:
            _eliminate(model)
        return model

    def entails_with_status(self, model, guard) -> dict:
        """Return entailed/not_entailed/unknown with resource diagnostics."""
        if not model.feasible_flag:
            self.last_result = {"status": "entailed", "queries": self.queries}
            return self.last_result
        for atom in atoms_of(guard):
            txt = str(atom).strip()
            if txt in ("(true)", "true"):
                continue
            if txt in ("(false)", "false"):
                self.last_result = {"status": "not_entailed", "queries": self.queries}
                return self.last_result
            try:
                la = parse_atom(txt)
            except LinearError:
                self.last_result = {"status": "not_entailed", "reason": "opaque guard",
                                    "queries": self.queries}
                return self.last_result
            # Each normalized guard conjunct needs its own negated probe.
            for n in _normalize(la):
                for neg in _negate_norm(n):
                    exhausted = self._consume_query()
                    if exhausted is not None:
                        self.last_result = {"status": "unknown", "reason": exhausted,
                                            "queries": self.queries}
                        return self.last_result
                    if _implication_probe_feasible(tuple(model.src), neg):
                        self.last_result = {"status": "not_entailed",
                                            "queries": self.queries}
                        return self.last_result
        self.last_result = {"status": "entailed", "queries": self.queries}
        return self.last_result

    def entails(self, model, guard) -> bool:
        """Legacy boolean API fails closed; use entails_with_status for UNKNOWN."""
        return self.entails_with_status(model, guard)["status"] == "entailed"

    def feasible(self, model) -> bool:
        """feasible(model): see module docstring."""
        return model.feasible_flag


# ---------------------------------------------------------------------------
# Differential harness: two engines must agree on every verdict
# ---------------------------------------------------------------------------

def differential(cases, engine_a, engine_b):
    """cases: iterable of atom-text lists. Returns disagreement list;
    empty == engines agree everywhere == certificate issued."""
    disagreements = []
    for i, atoms in enumerate(cases):
        ma, mb = engine_a.learn(atoms), engine_b.learn(atoms)
        va, vb = engine_a.feasible(ma), engine_b.feasible(mb)
        if va != vb:
            disagreements.append({"case": i, "atoms": list(atoms),
                                  "a": va, "b": vb})
    return disagreements
