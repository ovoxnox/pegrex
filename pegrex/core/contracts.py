"""Conservative operations over normalized path contracts."""
from __future__ import annotations
from collections.abc import Iterable
from .models import PathContract, contracts_from_pairs


def canonicalize(pairs: Iterable[tuple[Iterable[str], object]]) -> list[PathContract]:
    return contracts_from_pairs(pairs)


def as_legacy_pairs(contracts: Iterable[PathContract]) -> list[tuple[frozenset[str], str]]:
    """Compatibility adapter for the historical list[(frozenset, result)] API."""
    return [(frozenset(row.constraints), row.outcome) for row in contracts]


def subsume(paths: Iterable[PathContract]) -> dict:
    """Remove only syntactically stronger guards with identical result semantics.

    This is intentionally syntactic and conservative: it does not call an SMT
    solver and makes no claim that arbitrary formulas are equivalent.
    """
    rows = sorted(paths, key=lambda row: (row.outcome, len(row.constraints), row.constraints, row.identity))
    kept: list[PathContract] = []
    removed: list[dict] = []
    for row in rows:
        dominator = next((candidate for candidate in kept
                          if candidate.outcome == row.outcome
                          and set(candidate.constraints) < set(row.constraints)), None)
        if dominator:
            removed.append({"path": row.to_dict(), "subsumed_by": dominator.identity,
                            "reason": "same outcome; broader canonical guard set"})
        elif not any(existing.identity == row.identity for existing in kept):
            kept.append(row)
        else:
            duplicate = next(existing for existing in kept if existing.identity == row.identity)
            removed.append({"path": row.to_dict(), "subsumed_by": duplicate.identity,
                            "reason": "duplicate canonical contract"})
    return {"schema": "pegrex.contract-subsumption.v1",
            "kept": [row.to_dict() for row in kept], "removed": removed,
            "method": "syntactic-only; same-outcome required"}
