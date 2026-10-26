"""Loop-invariant inference with explicit initiation/consecution proofs.

Candidates survive only when both proof obligations are discharged. Missing
step information, solver budgets, and unsupported formulas remove candidates
from the proved set and are reported as UNKNOWN coverage.
"""
from __future__ import annotations

import re

from .ir import lower_condition
from .linsolve import LinearBackend, atoms_of

DEFAULT_LB = LinearBackend()


def _vars_of(atoms):
    out = set()
    for atom in atoms:
        out |= set(re.findall(r"[A-Za-z_]\w*", atom))
    return sorted(out)


def _consts_of(atoms):
    out = {0, 1}
    for atom in atoms:
        out |= {int(x) for x in re.findall(r"-?\d+", atom)}
    return sorted(out)


def _deltas_sym(deltas):
    return {name: (f"({name} + {delta})" if delta >= 0 else f"({name} - {-delta})")
            for name, delta in deltas.items()}


def _entails(lb, model, condition) -> str:
    if hasattr(lb, "entails_with_status"):
        return lb.entails_with_status(model, condition)["status"]
    try:
        return "entailed" if lb.entails(model, condition) else "not_entailed"
    except Exception:
        return "unknown"


def _primed(condition: str, deltas: dict[str, int]) -> str:
    out = condition
    for name in sorted(deltas, key=len, reverse=True):
        delta = deltas[name]
        if delta:
            out = re.sub(rf"\b{re.escape(name)}\b", f"({name} + {delta})", out)
    return out


def validate_invariants(guard_text, deltas, init_atoms, candidates, lb=None,
                        rounds: int = 6) -> dict:
    """Houdini validation of candidate linear invariants.

    ``deltas`` must describe every mutated variable used by a candidate.
    Static variables are represented explicitly by delta zero.
    """
    lb = lb or DEFAULT_LB
    guard_atoms = atoms_of(lower_condition(guard_text))
    init_model = lb.learn(list(init_atoms))  # guard is not an entry assumption
    alive: list[str] = []
    dropped_init: list[str] = []
    dropped_consec: list[str] = []
    unknowns: list[str] = []
    obligations: dict[str, dict] = {}

    for candidate in sorted(set(candidates)):
        try:
            verdict = _entails(lb, init_model, lower_condition(candidate))
        except Exception as exc:
            verdict = "unknown"
            unknowns.append(f"initiation parse failed for {candidate}: {exc}")
        obligations[candidate] = {"initiation": verdict, "consecution": "not_checked"}
        if verdict == "entailed":
            alive.append(candidate)
        else:
            dropped_init.append(candidate)
            if verdict == "unknown":
                unknowns.append(f"initiation undecided for {candidate}")

    for _ in range(rounds):
        if not alive:
            break
        assumptions = list(guard_atoms)
        for invariant in alive:
            assumptions.extend(atoms_of(lower_condition(invariant)))
        model = lb.learn(assumptions)
        still: list[str] = []
        for candidate in alive:
            variables = set(_vars_of([candidate]))
            missing = sorted(variables - set(deltas))
            if missing:
                dropped_consec.append(candidate)
                obligations[candidate]["consecution"] = "unknown"
                unknowns.append(f"no step model for {missing} in {candidate}")
                continue
            try:
                verdict = _entails(lb, model, lower_condition(_primed(candidate, deltas)))
            except Exception as exc:
                verdict = "unknown"
                unknowns.append(f"consecution parse failed for {candidate}: {exc}")
            obligations[candidate]["consecution"] = verdict
            if verdict == "entailed":
                still.append(candidate)
            else:
                dropped_consec.append(candidate)
                if verdict == "unknown":
                    unknowns.append(f"consecution undecided for {candidate}")
        if still == alive:
            break
        alive = still

    return {
        "schema": "pegrex.loop-invariants.v1",
        "status": "unknown" if unknowns else "ok",
        "invariants": sorted(alive),
        "validated": sorted(alive),
        "dropped_at_initiation": sorted(set(dropped_init)),
        "dropped_at_consecution": sorted(set(dropped_consec)),
        "unknowns": sorted(set(unknowns)),
        "proof_obligations": obligations,
        "guard": guard_text,
        "deltas": dict(deltas),
    }


def infer_invariants(guard_text, deltas, init_atoms, lb=None, rounds=6) -> dict:
    """Infer and validate linear templates; never retain unproved candidates."""
    guard_atoms = atoms_of(lower_condition(guard_text))
    guard_vars = set(_vars_of(guard_atoms))
    # Guard variables omitted from the transition map are read-only loop
    # parameters (for example n in i <= n). Variables absent from both the
    # guard and transition map are not promoted into invariant templates.
    effective_deltas = {name: 0 for name in guard_vars}
    effective_deltas.update(deltas)
    vars_ = sorted(guard_vars | set(deltas))
    consts = _consts_of(guard_atoms + list(init_atoms))
    static = [name for name in vars_ if effective_deltas.get(name) == 0]
    candidates = set()
    for name in vars_:
        for constant in consts:
            candidates.add(f"{name} >= {constant}")
            candidates.add(f"{name} <= {constant}")
        for other in static:
            if other != name:
                for constant in (0, 1):
                    candidates.add(f"{name} <= {other} + {constant}")
                    candidates.add(f"{name} >= {other} - {constant}")
    return validate_invariants(guard_text, effective_deltas, init_atoms, sorted(candidates),
                               lb=lb, rounds=rounds)


def _lhs_var(cond_text):
    match = re.match(r"^([A-Za-z_]\w*)\s*(>=|<=|<|>)", cond_text.strip())
    return match.group(1) if match else None
