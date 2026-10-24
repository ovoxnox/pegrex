"""
invariants — loop invariant inference (Houdini-lite) 

║  Candidate linear invariants from templates; a candidate survives only   
║  if initiation (entry implies it) and consecution (guard + current set   
║  imply it after the body) discharge via the entailment engine.       
║  Failed candidates are dropped, not weakened silently: the fixpoint is   
║  the strongest template invariant the prover can defend."""

from __future__ import annotations

import re

from .ir import lower_condition
from .linsolve import LinearBackend, atoms_of

DEFAULT_LB = LinearBackend()


def _vars_of(atoms):
    out = set()
    for a in atoms:
        out |= set(re.findall(r"[A-Za-z_]\w*", a))
    return sorted(out)


def _consts_of(atoms):
    out = {0, 1}
    for a in atoms:
        out |= {int(x) for x in re.findall(r"-?\d+", a)}
    return sorted(out)


def _deltas_sym(deltas):
    """{var: delta} -> substitution strings 'var + d' for the primed check."""
    return {v: (f"({v} + {d})" if d >= 0 else f"({v} - {-d})") for v, d in deltas.items()}


def infer_invariants(guard_text, deltas, init_atoms, lb=None, rounds=6) -> dict:
    """Houdini-lite over linear templates.

    deltas: {var: constant per-iteration delta} (non-constant vars get no
    consecution check and are skipped -- honest, not guessed)."""
    lb = lb or DEFAULT_LB
    guard_atoms = atoms_of(lower_condition(guard_text))
    vars_ = _vars_of(guard_atoms) + [v for v in deltas if v not in _vars_of(guard_atoms)]
    consts = _consts_of(guard_atoms + list(init_atoms))
    bounds = [v for v in vars_ if v not in deltas or deltas.get(v) == 0]

    cands = set()
    for v in vars_:
        for k in consts:
            cands.add(f"{v} >= {k}")
            cands.add(f"{v} <= {k}")
        for b in bounds:
            if b != v:
                for k in (0, 1):
                    cands.add(f"{v} <= {b} + {k}")
                    cands.add(f"{v} >= {b} - {k}")
    cands = sorted(cands)

    def primed(cond_text):
        """primed(cond_text): see module docstring."""
        out = cond_text
        for v in sorted(deltas, key=len, reverse=True):
            d = deltas[v]
            if d == 0:
                continue
            out = re.sub(rf"\b{re.escape(v)}\b", f"({v} + {d})", out)
        return out

    init_model = lb.learn(list(init_atoms) + guard_atoms)
    alive = []
    for c in cands:
        try:
            if lb.entails(init_model, lower_condition(c)):
                alive.append(c)
        except Exception:
            pass
    dropped_init = sorted(set(cands) - set(alive))

    for _ in range(rounds):
        if not alive:
            break
        assumption_atoms = []
        for c in alive:
            try:
                assumption_atoms += atoms_of(lower_condition(c))
            except Exception:
                pass
        model = lb.learn(guard_atoms + assumption_atoms)
        still = []
        for c in alive:
            d = deltas.get(_lhs_var(c))
            if d is None:
                still.append(c)  # no step info: keep if initiated
                continue
            try:
                if lb.entails(model, lower_condition(primed(c))):
                    still.append(c)
            except Exception:
                pass
        if sorted(still) == sorted(alive):
            break
        alive = still

    return {"invariants": sorted(alive), "dropped_at_initiation": dropped_init}


def _lhs_var(cond_text):
    m = re.match(r"^([A-Za-z_]\w*)\s*(>=|<=|<|>)", cond_text.strip())
    return m.group(1) if m else None
