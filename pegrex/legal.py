"""legal.py -- legal-contract DSL: obligations/deadlines as path constraints.
A clause is (party, obligation, deadline); the contract's paths must reach
every obligation before its deadline."""
from __future__ import annotations

import re

CLAUSE_RE = re.compile(
    r"(\w+)\s+(?:shall|must)\s+([\w\s]+?)\s+within\s+(\d+)\s+days",
    re.I)


def parse_clauses(text: str) -> list:
    return [{"party": m.group(1), "obligation": m.group(2).strip(),
             "deadline": int(m.group(3))}
            for m in CLAUSE_RE.finditer(text)]


def obligations_as_constraints(clauses) -> list:
    """Each clause -> a constraint the workflow must satisfy (deadline bound)."""
    from .sym import V, const, Le
    return [Le(V(f"{c['party']}.{c['obligation']}.days"),
               const(c["deadline"])) for c in clauses]
