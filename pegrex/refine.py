"""
refine — refinement contracts as comments (Dafny-lite) 

║  `# requires: <cond>` / `# ensures: <cond>` parsed from source and      
║  discharged per path by the entailment engine. Every verdict is     
║  one of discharged (|= E) / violated (|= ~E) / undischarged (neither)   
║  -- an undischarged contract is reported, never assumed."""

from __future__ import annotations

import re

from .ir import cond_to_atom, lower_condition
from .linsolve import LinearBackend, parse_atom

DEFAULT_LB = LinearBackend()


def parse_contracts(src_text: str, lang: str = "python") -> dict:
    """parse contracts(src_text, lang): see module docstring."""
    from .annotations import annotated
    return {
        "requires": annotated(src_text, lang, "requires"),
        "ensures": annotated(src_text, lang, "ensures"),
    }


def _norm_constraint(c: str) -> str:
    """String constraint -> normalized atom text via the m76 seam.
    `(not (n >= 0))` flips to `(1*n < 0)`; opaque stays opaque (dropped by
    the solver -- the safe direction: less information, never false proof)."""
    try:
        return cond_to_atom(lower_condition(c.strip()))
    except Exception:
        return c


def discharge(path_constraints, result, contracts, lb=None) -> dict:
    """One path's verdicts against the refinement contracts."""
    lb = lb or DEFAULT_LB
    atoms = []
    for c in path_constraints:
        n = _norm_constraint(str(c))
        try:
            parse_atom(n)   # raises LinearError if opaque
            atoms.append(n)
        except Exception:
            pass            # opaque: dropped, safe direction
    model = lb.learn(atoms)
    out = {"requires": [], "ensures": []}
    for r in contracts["requires"]:
        try:
            rs = lower_condition(r)
            neg_probe = lb.learn(atoms + [cond_to_atom(_neg(rs))])
            out["requires"].append(
                {"contract": r, "status":
                 "violated" if neg_probe.feasible() else "respected"})
        except Exception:
            out["requires"].append({"contract": r, "status": "undischarged"})
    for e in contracts["ensures"]:
        sub = re.sub(r"\bresult\b", f"({result})", e)
        try:
            es = lower_condition(sub)
            es_neg = _neg(es)
            pos = lb.entails(model, es)
            neg = lb.entails(model, es_neg)
            out["ensures"].append({"contract": e, "substituted": sub,
                                   "status": "violated" if neg else
                                             "discharged" if pos else
                                             "undischarged"})
        except Exception:
            out["ensures"].append({"contract": e, "substituted": sub,
                                   "status": "undischarged"})
    return out


def _neg(sym_cond):
    from .sym import Op
    if isinstance(sym_cond, Op) and sym_cond.op == "not" and len(sym_cond.args) == 1:
        return sym_cond.args[0]  # negation of a negation
    if isinstance(sym_cond, Op) and sym_cond.op in ("<", "<=", ">", ">=", "="):
        flip = {"<": ">=", "<=": ">", ">": "<=", ">=": "<", "=": "!="}[sym_cond.op]
        return Op(flip, sym_cond.args)
    return Not(sym_cond)


def discharge_source(src_path, contracts, lb=None) -> list:
    """All paths of a source file, each with its verdicts."""
    from . import api
    out = []
    for cs, res in api.contracts(src_path):
        out.append({"constraints": sorted(map(str, cs)), "result": str(res),
                    **discharge(cs, str(res), contracts, lb)})
    return out
