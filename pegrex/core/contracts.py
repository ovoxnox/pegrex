"""Conservative operations over normalized path contracts."""
from __future__ import annotations
from collections.abc import Iterable
from .models import PathContract, contracts_from_pairs


def canonicalize(pairs: Iterable[tuple[Iterable[str], object]]) -> list[PathContract]:
    """Implement canonicalize with the module's explicit API and failure semantics."""
    return contracts_from_pairs(pairs)


def as_legacy_pairs(contracts: Iterable[PathContract]) -> list[tuple[frozenset[str], str]]:
    """Compatibility adapter for the historical list[(frozenset, result)] API."""
    return [(frozenset(row.constraints), row.outcome) for row in contracts]


def _observable_behavior(row: PathContract, semantic: bool):
    if not semantic:
        return row.outcome, row.function
    from ..semantics import _canon_result
    # Source locations and hashes are provenance, not behavior. Explicit
    # effect/exception metadata is observable and therefore must agree.
    observable_keys = {"effect", "effects", "side_effects", "raises", "exception", "io"}
    effects = tuple(sorted((key, value) for key, value in row.metadata
                           if key in observable_keys))
    return (_canon_result(row.outcome), effects), row.function


def subsume(paths: Iterable[PathContract], *, semantic: bool = False) -> dict:
    """Remove paths covered by a less restrictive, behavior-equivalent path.

    The default retains the historical syntactic operation. ``semantic=True``
    additionally canonicalizes linear outcomes and uses memoized QF_LIA
    implication. Undecided or opaque pairs are kept and reported, never
    discarded as redundant.
    """
    rows = sorted(paths, key=lambda row: (str(_observable_behavior(row, semantic)),
                                          len(row.constraints), row.constraints, row.identity))
    kept: list[PathContract] = []
    removed: list[dict] = []
    unknowns: list[str] = []
    identities: dict[str, str] = {}
    for row in rows:
        behavior, function = _observable_behavior(row, semantic)
        dominator = None
        reason = ""
        for candidate in kept:
            candidate_behavior, candidate_function = _observable_behavior(candidate, semantic)
            if candidate_behavior != behavior or candidate_function != function:
                continue
            candidate_constraints = set(candidate.constraints)
            row_constraints = set(row.constraints)
            if candidate_constraints < row_constraints:
                dominator, reason = candidate, "same observable behavior; broader canonical guard set"
                break
            if candidate_constraints == row_constraints and candidate.outcome == row.outcome:
                dominator, reason = candidate, "duplicate canonical contract"
                break
            if semantic:
                verdict = __import__("pegrex.constraints", fromlist=["implies"]).implies(
                    row.constraints, candidate.constraints)
                identities[row.identity] = verdict["assumptions"]
                identities[candidate.identity] = verdict["conclusions"]
                if verdict["status"] == "entailed":
                    dominator, reason = candidate, "same observable behavior; QF_LIA guard implication"
                    break
                if verdict["status"] == "unknown":
                    unknowns.extend(f"subsumption undecided: {candidate.identity} -> {row.identity}: {reason}"
                                    for reason in verdict["unknowns"])
        if dominator is not None:
            removed.append({"path": row.to_dict(), "subsumed_by": dominator.identity,
                            "reason": reason})
        elif not any(existing.identity == row.identity for existing in kept):
            kept.append(row)
        else:
            duplicate = next(existing for existing in kept if existing.identity == row.identity)
            removed.append({"path": row.to_dict(), "subsumed_by": duplicate.identity,
                            "reason": "duplicate canonical contract"})
    report = {"schema": "pegrex.contract-subsumption.v1",
              "kept": [row.to_dict() for row in kept], "removed": removed,
              "method": ("syntactic + canonical QF_LIA implication; "
                         "same observable outcome/effects required")
                         if semantic else "syntactic-only; same-outcome required"}
    if semantic:
        report["unknowns"] = sorted(set(unknowns))
        report["constraint_identities"] = identities
    return report
