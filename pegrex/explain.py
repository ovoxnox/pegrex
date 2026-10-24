"""explain.py -- 'explain this function as math': natural-language rendering of a contract."""
from __future__ import annotations


def explain(contract, fn: str = "function") -> str:
    """[(constraints, result)] -> readable sentences."""
    lines = [f"{fn} has {len(contract)} execution path(s):"]
    for cons, res in contract:
        cs = sorted(cons)
        when = " AND ".join(c for c in cs if not c.startswith("(not ")) or "always"
        neg = [c[5:-1] for c in cs if c.startswith("(not ")]
        if neg:
            when += " AND NOT (" + " OR ".join(neg) + ")"
        lines.append(f"- when {when}: returns {res}")
    return chr(10).join(lines)
