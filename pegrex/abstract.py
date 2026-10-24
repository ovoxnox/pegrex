"""
abstract -- abstract interpretation (interval domain)
Sound over-approximation of variable ranges via the SMT bounds models.
Complements path constraints: WHERE paths go vs WHAT values they hold.
"""
from __future__ import annotations

from .smt import learn


def interval_analysis(atoms) -> dict:
    """atoms -> {var: (lo, hi)} with infinities as None.  Sound: every
    concrete value any model of atoms can take lies in [lo, hi]."""
    m = learn(atoms)
    out = {}
    for var, (lo, li, hi, hi_inc, _neq) in m.bounds.items():
        out[var] = (lo if lo is not None else float("-inf"),
                    hi if hi is not None else float("inf"))
    return out
