"""Model-guided counterexample minimization with reproduction evidence."""
from __future__ import annotations
from fractions import Fraction
import math
from .linsolve import parse_atom, LinearError

SCHEMA = "pegrex.counterexample-minimization.v1"


def _valid(constraints, model):
    try:
        for text in constraints:
            atom = parse_atom(text)
            values = {name: model[name] for name, _ in atom.coeffs}
            left = sum(coeff * Fraction(values[name]) for name, coeff in atom.coeffs)
            operations = {"<=": left <= atom.k, ">=": left >= atom.k,
                          "<": left < atom.k, ">": left > atom.k,
                          "=": left == atom.k, "!=": left != atom.k}
            if not operations[atom.op]:
                return False
        return True
    except (KeyError, TypeError, ValueError, LinearError):
        return None



def _boundaries(constraints, model, name):
    """Integer candidates at constraint boundaries under the current model."""
    candidates = []
    for text in constraints:
        try:
            atom = parse_atom(text)
            coefficients = dict(atom.coeffs)
            coefficient = coefficients.get(name, Fraction(0))
            if not coefficient: continue
            rest = sum(coeff * Fraction(model[var]) for var, coeff in atom.coeffs if var != name)
            boundary = (atom.k - rest) / coefficient
            for base in (math.floor(boundary), math.ceil(boundary)):
                candidates.extend((base - 1, base, base + 1))
        except (LinearError, KeyError, TypeError, ValueError):
            continue
    return candidates

def minimize_symbolic_witness(constraints, model, *, reproduce=None) -> dict:
    """Shrink model values while preserving constraints and optional execution.

    This is model/domain minimization, not source-text delta debugging. Every
    accepted candidate is checked against the original symbolic constraints.
    """
    constraints = list(constraints)
    current = dict(model)
    initial = _valid(constraints, current)
    unknowns = []
    if initial is not True:
        return {"schema": SCHEMA, "schema_version": 1, "confirmed": False,
                "verdict": "unknown", "original": dict(model), "minimized": dict(model),
                "attempts": [], "unknowns": ["original witness does not satisfy the supported constraints"]}
    if reproduce is not None:
        try:
            if reproduce(current) is not True:
                return {"schema": SCHEMA, "schema_version": 1, "confirmed": False,
                        "verdict": "unknown", "original": dict(model), "minimized": dict(model),
                        "attempts": [], "unknowns": ["original witness did not reproduce"]}
        except Exception as error:
            return {"schema": SCHEMA, "schema_version": 1, "confirmed": False,
                    "verdict": "unknown", "original": dict(model), "minimized": dict(model),
                    "attempts": [], "unknowns": [f"reproducer error: {error}"]}
    attempts = []
    def accepts(candidate):
        """Implement accepts with the module's explicit API and failure semantics."""
        valid = _valid(constraints, candidate)
        if valid is not True:
            return False
        if reproduce is not None:
            try:
                return reproduce(candidate) is True
            except Exception as error:
                unknowns.append(f"reproducer error: {error}")
                return False
        return True
    for name in sorted(current):
        value = current[name]
        if isinstance(value, bool):
            candidates = [False]
        elif isinstance(value, int):
            candidates = [0, 1, -1] + _boundaries(constraints, current, name)
            magnitude = abs(value)
            while magnitude > 1:
                magnitude //= 2
                candidates.extend([magnitude, -magnitude] if value >= 0 else [-magnitude, magnitude])
        elif isinstance(value, str):
            candidates = [""]
            size = len(value)
            while size > 1:
                size //= 2
                candidates.append(value[:size])
        else:
            continue
        candidates = sorted(set(candidates), key=lambda row: (abs(row), row)) if isinstance(value, (int, bool)) else candidates
        for candidate_value in candidates:
            if candidate_value == current[name]:
                continue
            if isinstance(value, int) and not isinstance(value, bool) and abs(candidate_value) >= abs(current[name]):
                continue
            if isinstance(value, str) and len(candidate_value) >= len(current[name]):
                continue
            candidate = dict(current, **{name: candidate_value})
            accepted = accepts(candidate)
            attempts.append({"variable": name, "candidate": candidate_value,
                             "accepted": accepted})
            if accepted:
                current = candidate
    return {"schema": SCHEMA, "schema_version": 1, "confirmed": True,
            "verdict": "refuted", "original": dict(model), "minimized": current,
            "attempts": attempts, "unknowns": unknowns,
            "evidence": {"method": "constraint-preserving model shrink",
                         "reproduced": reproduce is not None}}
