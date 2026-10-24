"""
veritest — state merging via projection 

║  Paths that differ only in dead variables merge: project each path's    
║  constraints onto the live set (FM elimination of the dead vars) and    
║  dedupe. This is veritesting's tractable core: merging is sound (the    
║  projection over-approximates exactly the dead dimensions) and it can   
║  collapse exponentially many paths into one. Live-variable differences  
║  never merge -- checked, not assumed."""

from __future__ import annotations

from .ir import cond_to_atom, lower_condition
from .linsolve import (LinearBackend, _combine, _normalize, _unit_bounds,
                       atoms_of, parse_atom)
from .refine import _neg, _norm_constraint
from .semantics import _canon_result

DEFAULT_LB = LinearBackend()


def _norm_atoms(constraints):
    out = []
    for c in constraints:
        n = _norm_constraint(str(c))
        try:
            la = parse_atom(n)
        except Exception:
            return None  # opaque: unprojectable, no merge
        for x in _normalize(la):
            out.append(x)
    return out


def _txt(coeffs, k):
    terms = []
    for v, cf in sorted(coeffs.items()):
        terms.append(f"{cf}*{v}")
    return "(" + (" + ".join(terms).replace("+ -", "- ") or "0") + f" <= {k})"


def project(atoms, keep):
    """FM-eliminate every variable not in `keep`. Returns atom-text list or
    None if any constraint is outside the linear fragment."""
    norm = _norm_atoms(atoms)
    if norm is None:
        return None
    ineqs = [(x.cd(), x.k) for x in norm]
    drop = sorted({v for c, _ in ineqs for v in c} - set(keep))
    for var in drop:
        highs, lows, others = _unit_bounds(ineqs, var)
        new = list(others)
        for h in highs:
            for l in lows:
                new.append(_combine(h, l))
        ineqs = new
    return [_txt(c, k) for c, k in ineqs]


def merge_paths(contracts, keep):
    """contracts: [(frozenset(constraints), result)]. Returns merged list of
    {constraints: [atom texts], result: canonical}. Only dead-variable
    differences collapse; live differences stay separate."""
    groups = {}
    for cs, res in contracts:
        patoms = [str(c) for c in cs]
        proj = project(patoms, keep)
        if proj is None:
            key = ("raw", frozenset(patoms), _canon_result(res))
        else:
            key = ("proj", frozenset(proj), _canon_result(res))
        groups.setdefault(key, (proj if proj is not None else patoms,
                                str(res)))
    return [{"constraints": sorted(v), "result": k[2], "result_expr": rexpr}
            for k, (v, rexpr) in sorted(groups.items(), key=lambda kv: str(kv[0]))]


def check_merged(merged, prop_text, lb=None):
    """Property over the merged path set: proven (every disjunct entails P),
    violated (~P entailed on some disjunct, with witness), or unknown.
    `result` in the property is substituted by each path's result_expr."""
    import re
    lb = lb or DEFAULT_LB
    for path in merged:
        sub = re.sub(r"\bresult\b", f"({path['result_expr']})", prop_text)
        try:
            prop = lower_condition(sub)
            neg = _neg(prop)
        except Exception:
            return {"status": "unknown", "path": path,
                    "reason": "property outside the fragment"}
        model = lb.learn(path["constraints"])
        try:
            if model.feasible() and lb.entails(model, neg):
                return {"status": "violated", "path": path,
                        "witness": model.model()}
        except Exception:
            pass
    for path in merged:
        sub = re.sub(r"\bresult\b", f"({path['result_expr']})", prop_text)
        try:
            prop = lower_condition(sub)
        except Exception:
            return {"status": "unknown", "path": path}
        model = lb.learn(path["constraints"])
        try:
            if not model.feasible():
                continue  # infeasible disjunct: vacuous
            if not lb.entails(model, prop):
                return {"status": "unknown", "path": path}
        except Exception:
            return {"status": "unknown", "path": path}
    return {"status": "proven", "disjuncts": len(merged)}
