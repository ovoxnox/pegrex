"""
formalize -- natural language -> formal invariants 

║  Template-based NL -> path-constraint extraction with contract           
║  validation.  'withdrawals must not exceed balance' ->                  
║  (amount <= balance) checked against the AgentReport's own paths."""

from __future__ import annotations

import re

_TEMPLATES = [
    (r"(\w+)\s+must not exceed\s+(\w+)",
     lambda m: ("<=", m.group(1), m.group(2))),
    (r"(\w+)\s+must be (?:at least|>=)\s+(\w+|[+-]?\d+)",
     lambda m: (">=", m.group(1), m.group(2))),
    (r"(\w+)\s+must be (?:less than|<)\s+(\w+|[+-]?\d+)",
     lambda m: ("<", m.group(1), m.group(2))),
    (r"(\w+)\s+must equal\s+(\w+|[+-]?\d+)",
     lambda m: ("==", m.group(1), m.group(2))),
]


def formalize(text: str) -> list:
    """NL invariant sentences -> [(op, lhs, rhs), ...]."""
    out = []
    for rx, mk in _TEMPLATES:
        for m in re.finditer(rx, text, re.I):
            out.append(mk(m))
    return out


def invariant_to_constraint(inv):
    """Implement invariant to constraint with the module's explicit API and failure semantics."""
    from .sym import V, const, Le, Ge, Lt, Eq
    op, lhs, rhs = inv
    lv = V(lhs)
    rv = const(int(rhs)) if str(rhs).lstrip("+-").isdigit() else V(rhs)
    return {"<=": Le, ">=": Ge, "<": Lt, "==": Eq}[op](lv, rv)


def check_invariant(report_paths, inv) -> bool:
    """True if the invariant's constraint appears in some path's constraints
    (or its negation absent -- i.e. no path violates it)."""
    c = str(invariant_to_constraint(inv))
    allc = [x for p in report_paths for x in p]
    return c in allc or ("(not " + c + ")") not in allc
