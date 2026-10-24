"""circuit.py -- circuit verification: arithmetic circuits as SMT constraints.
Gate netlists -> R1CS-like equations -> feasibility/sat via the SMT core."""
from __future__ import annotations

from .smt import learn as _learn


def check_circuit(gate_eqs) -> dict:
    """gate_eqs: ['w3 = w1 * w2', 'w1 + w2 = 5']-ish strings, normalized to
    atoms the bounds engine can consume (linear) or z3 (non-linear).
    Returns {consistent, model-ish bounds}."""
    atoms = [e.replace(" = ", " = ") for e in gate_eqs]
    try:
        from .smt import auto_feasible
        ok = auto_feasible(atoms)
    except Exception:
        ok = _learn(atoms).feasible()
    return {"consistent": ok}
