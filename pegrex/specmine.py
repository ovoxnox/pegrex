"""
specmine — spec mining from path contracts (Daikon-style) 

║  Candidate invariants from linear templates over vars + result; each    
║  candidate is classified, never asserted:                               
║    proven   -- entailed on every path (FM discharge)                    
║    likely   -- consistent with all sampled engine models                
║    dropped  -- contradicted on some path (negation entailed or a        
║                sampled model violates it) 

║  Mined specs are proposals for review; only 'proven' may be trusted."""

from __future__ import annotations

import re

from .ir import cond_to_atom, lower_condition
from .linsolve import LinearBackend, atoms_of, parse_atom
from .strategies import sample_models

DEFAULT_LB = LinearBackend()


def _norm(c):
    from .refine import _norm_constraint
    return _norm_constraint(c)


def _path_atoms(constraints, lb):
    atoms = []
    for c in constraints:
        n = _norm(str(c))
        try:
            parse_atom(n)
            atoms.append(n)
        except Exception:
            pass
    return atoms


def _consts(atoms):
    out = {0}
    for a in atoms:
        out |= {int(x) for x in re.findall(r"-?\d+", a)}
    return sorted(out)


def candidates_of(paths_atoms, results):
    """Linear template instances over vars and `result`."""
    vars_ = sorted({v for atoms in paths_atoms for a in atoms
                    for v in re.findall(r"[A-Za-z_]\w*", a)})
    consts = _consts([a for atoms in paths_atoms for a in atoms])
    cands = []
    for v in vars_:
        cands += [f"{v} >= 0", f"{v} <= 0"] + [f"{v} <= {k}" for k in consts if k > 0] \
                                       + [f"{v} >= {k}" for k in consts if k < 0]
    for r in set(results):
        cands += [f"result >= 0", f"result <= 0"]
        for v in vars_:
            cands += [f"result >= {v}", f"result <= {v}"]
    seen, out = set(), []
    for c in cands:
        if c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _atom_holds(la, sample) -> bool:
    """One linear atom evaluated against one concrete sample.
    Lazy per-operator comparison (the old eager dict built all six)."""
    total = sum(c * sample.get(v, 0) for v, c in la.cd().items())
    if la.op == "<=":
        return total <= la.k
    if la.op == ">=":
        return total >= la.k
    if la.op == "=":
        return total == la.k
    if la.op == "!=":
        return total != la.k
    if la.op == "<":
        return total < la.k
    return total > la.k


def _substituted_atoms(cand: str, result_expr: str):
    """Candidate with `result` replaced by the path result expression,
    lowered to solver atoms. None when outside the linear fragment --
    such a path carries no confirming evidence either way."""
    sub = re.sub(r"\bresult\b", "(%s)" % result_expr, cand)
    try:
        return atoms_of(lower_condition(sub))
    except Exception:
        return None


def _path_confirms(atoms, samples) -> bool:
    """True iff every sample satisfies every parseable atom.
    One violating sample is decisive (early exit, no flag cascade);
    unparseable atoms are skipped -- they cannot confirm anything."""
    for sample in samples:
        for atom in atoms:
            try:
                la = parse_atom(atom)
            except Exception:
                continue
            if not _atom_holds(la, sample):
                return False
    return True


def _holds_on_all_paths(cand: str, results, models) -> bool:
    """The `likely` verdict: no sampled witness contradicts the candidate
    on any path. Paths outside the fragment are skipped (no evidence);
    an empty path is vacuously consistent."""
    for pi, path_samples in enumerate(models):
        atoms = _substituted_atoms(cand, results[pi])
        if atoms is None:
            continue
        if not _path_confirms(atoms, path_samples):
            return False
    return True

def mine(src_path, lb=None, samples_per_path=4):
    """Mine candidate invariants for a source file's contracts."""
    lb = lb or DEFAULT_LB
    from . import api
    paths = [(sorted(map(str, cs)), str(res)) for cs, res in api.contracts(src_path)]
    paths_atoms = [_path_atoms(cs, lb) for cs, _ in paths]
    results = [r for _, r in paths]
    models = []
    for atoms in paths_atoms:
        models.append(sample_models(atoms, n=samples_per_path, lb=lb))
    proven, likely, dropped = [], [], []
    for cand in candidates_of(paths_atoms, results):
        subs = []
        for (_, res) in paths:
            subs.append(cand)
        # entailment per path
        entailed, contradicted = True, False
        for atoms, (_, res) in zip(paths_atoms, paths):
            if not atoms:
                entailed = False
                continue
            model = lb.learn(atoms)
            sub = re.sub(r"\bresult\b", f"({res})", cand)
            try:
                es = lower_condition(sub)
                from .refine import _neg
                if lb.entails(model, es):
                    continue
                if lb.entails(model, _neg(es)):
                    contradicted = True
                    break
                entailed = False
            except Exception:
                entailed = False
        if contradicted:
            dropped.append(cand)
            continue
        if entailed:
            proven.append(cand)
            continue
        # likely: every sampled model satisfies the candidate on every path
        (likely if _holds_on_all_paths(cand, results, models) else dropped).append(cand)
    return {"proven": sorted(proven), "likely": sorted(likely),
            "dropped": sorted(dropped)}
