"""
nlspec — NL -> spec -> proof 

║  A pluggable proposerturns natural language into candidate invariants; 
║  the checker classifies each against the function's real path contracts 
║  (m94 machinery): proven / likely / dropped. The proposer is never      
║  trusted: unverifiable proposals are rejected loudly. Built-in          
║  proposer extends formalize's templates; external LLMs plug into the same seam."""

from __future__ import annotations

import re

from .specmine import mine

_TEMPLATES = [
    (r"(\w+)\s+is (?:non-negative|never negative|always >= 0)",
     lambda m: f"{m.group(1)} >= 0"),
    (r"(\w+)\s+is (?:non-positive|never positive|always <= 0)",
     lambda m: f"{m.group(1)} <= 0"),
    (r"(\w+)\s+is (?:positive|greater than zero)",
     lambda m: f"{m.group(1)} > 0"),
    (r"the result (?:is|must be) (?:non-negative|at least 0)",
     lambda m: "result >= 0"),
    (r"(\w+)\s+must not exceed\s+(\w+)",
     lambda m: f"{m.group(1)} <= {m.group(2)}"),
    (r"(\w+)\s+is at most\s+(\w+|[+-]?\d+)",
     lambda m: f"{m.group(1)} <= {m.group(2)}"),
    (r"result is at least\s+(\w+)",
     lambda m: f"result >= {m.group(1)}"),
]


def propose(nl_text):
    """Built-in template proposer. Returns [] when nothing matches --
    a refusal, never an invention."""
    out = []
    for rx, fn in _TEMPLATES:
        for m in re.finditer(rx, nl_text, re.I):
            cand = fn(m)
            if cand not in out:
                out.append(cand)
    return out


def check(src_path, candidates=None, nl_text=None, lb=None):
    """Classify proposals against the source's path contracts.

    Returns per-candidate: proven (entailed on every path) / dropped
    (contradicted) / unknown (not decidable on the linear fragment)."""
    from . import api
    from .ir import lower_condition
    from .linsolve import LinearBackend, atoms_of, parse_atom
    from .refine import _neg
    lb = lb or LinearBackend()
    cands = candidates if candidates is not None else propose(nl_text or "")
    paths = []
    for cs, res in api.contracts(src_path):
        atoms = []
        for c in cs:
            from .refine import _norm_constraint
            n = _norm_constraint(str(c))
            try:
                parse_atom(n)
                atoms.append(n)
            except Exception:
                pass
        paths.append((atoms, str(res)))
    out = []
    for cand in cands:
        sub_variants = [cand]
        if "result" in cand:
            sub_variants = [re.sub(r"\bresult\b", f"({res})", cand)
                            for _, res in paths]
        status = "proven"
        for pi, (atoms, res) in enumerate(paths):
            sub = sub_variants[pi] if "result" in cand else cand
            try:
                es = lower_condition(sub)
            except Exception:
                status = "unknown"
                break
            model = lb.learn(atoms)
            if not atoms:
                status = "unknown"
                break
            if lb.entails(model, es):
                continue
            if lb.entails(model, _neg(es)):
                status = "dropped"
                break
            status = "unknown"
            break
        out.append({"candidate": cand, "status": status})
    return out
