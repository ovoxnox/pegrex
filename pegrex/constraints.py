"""Canonical constraint identities and memoized QF_LIA implication queries.

Only constraints whose complete semantics are understood receive a semantic
identity. Opaque formulas retain an exact surface identity and can never be
treated as proved merely because a solver skipped them.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from functools import lru_cache
from typing import Iterable

from .ir import lower_condition
from .linsolve import LinearBackend, LinearError, _normalize, _txt, parse_atom

SCHEMA = "pegrex.canonical-constraints.v1"


@dataclass(frozen=True)
class CanonicalConstraints:
    original: tuple[str, ...]
    canonical: tuple[str, ...]
    digest: str
    semantic: bool
    unknowns: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        """Implement to dict with the module's explicit API and failure semantics."""
        return {
            "schema": SCHEMA,
            "constraints": list(self.original),
            "canonical": list(self.canonical),
            "identity": self.digest,
            "identity_kind": "semantic-qf-lia" if self.semantic else "exact-surface",
            "unknowns": list(self.unknowns),
        }


def _normalized_text(text: str) -> tuple[list[str], str | None]:
    stripped = " ".join(str(text).strip().split())
    if stripped in {"true", "(true)"}:
        return [], None
    if stripped in {"false", "(false)"}:
        return ["(false)"], None
    try:
        atom = parse_atom(stripped)
    except LinearError:
        # Contract APIs historically also expose prefix conditions such as
        # ``(not (x = 0))``. Reuse the established lowering adapter.
        from .refine import _norm_constraint
        normalized = _norm_constraint(stripped)
        if normalized == stripped:
            return [stripped], f"outside canonical QF_LIA fragment: {stripped}"
        try:
            atom = parse_atom(normalized)
        except LinearError:
            return [normalized], f"outside canonical QF_LIA fragment: {stripped}"
    try:
        normalized_atoms = _normalize(atom)
    except LinearError as exc:
        return [stripped], str(exc)
    result = []
    for item in normalized_atoms:
        coeffs = list(item.coeffs)
        if not coeffs:
            value = sum(()) <= item.k if item.op == "<=" else 0 != item.k
            if value:
                continue
            return ["(false)"], None
        # Divide only when every coefficient and the bound are exactly
        # divisible. This preserves integer semantics (2*x <= 3 is not x <= 1).
        divisor = 0
        for _, coefficient in coeffs:
            divisor = math.gcd(divisor, abs(coefficient.numerator))
        if divisor > 1 and item.k.denominator == 1 and item.k.numerator % divisor == 0:
            coeffs = [(name, coefficient / divisor) for name, coefficient in coeffs]
            item = type(item)(tuple(coeffs), item.op, item.k / divisor)
        result.append(_txt(item))
    return sorted(set(result)), None


def canonicalize_constraints(constraints: Iterable[object]) -> CanonicalConstraints:
    """Implement canonicalize constraints with the module's explicit API and failure semantics."""
    original = tuple(sorted({" ".join(str(row).strip().split()) for row in constraints}))
    canonical: list[str] = []
    unknowns: list[str] = []
    for row in original:
        atoms, error = _normalized_text(row)
        canonical.extend(atoms)
        if error:
            unknowns.append(error)
    canonical_tuple = tuple(sorted(set(canonical)))
    semantic = not unknowns
    identity = {
        "kind": "semantic-qf-lia" if semantic else "exact-surface",
        "constraints": list(canonical_tuple) if semantic else list(original),
    }
    encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return CanonicalConstraints(original, canonical_tuple,
                                "sha256:" + hashlib.sha256(encoded).hexdigest(),
                                semantic, tuple(unknowns))


def constraint_hash(constraints: Iterable[object]) -> str:
    """Return a stable semantic hash for supported QF_LIA, exact otherwise."""
    return canonicalize_constraints(constraints).digest


@lru_cache(maxsize=8192)
def _cached_linear_implication(assumptions: tuple[str, ...],
                               conclusions: tuple[str, ...]) -> str:
    backend = LinearBackend()
    model = backend.learn(assumptions)
    for conclusion in conclusions:
        if conclusion in assumptions:
            continue
        try:
            guard = lower_condition(conclusion)
        except Exception:
            return "unknown"
        verdict = backend.entails_with_status(model, guard)["status"]
        if verdict != "entailed":
            return verdict
    return "entailed"


def implies(assumptions: Iterable[object], conclusions: Iterable[object]) -> dict:
    """Decide ``assumptions |= conclusions`` with explicit UNKNOWN and reuse.

    The cache key contains canonical constraint semantics, never object ids,
    process-randomized hashes, paths, or mtimes.
    """
    left = canonicalize_constraints(assumptions)
    right = canonicalize_constraints(conclusions)
    base = {
        "assumptions": left.digest,
        "conclusions": right.digest,
        "queries": len(right.canonical),
    }
    if not right.original:
        return {**base, "status": "entailed", "unknowns": []}
    if not left.semantic or not right.semantic:
        if set(right.original) <= set(left.original):
            return {**base, "status": "entailed", "unknowns": [],
                    "method": "exact-opaque-assumption"}
        return {**base, "status": "unknown",
                "unknowns": list(left.unknowns + right.unknowns) or
                            ["opaque constraint implication is undecided"]}
    if "(false)" in left.canonical:
        return {**base, "status": "entailed", "unknowns": [],
                "method": "infeasible-assumptions"}
    status = _cached_linear_implication(left.canonical, right.canonical)
    return {**base, "status": status,
            "unknowns": ["linear implication was not decided"] if status == "unknown" else [],
            "method": "memoized-canonical-qf-lia"}


def cache_info() -> dict:
    """Implement cache info with the module's explicit API and failure semantics."""
    info = _cached_linear_implication.cache_info()
    return {"hits": info.hits, "misses": info.misses,
            "maxsize": info.maxsize, "size": info.currsize}


def clear_cache() -> None:
    """Implement clear cache with the module's explicit API and failure semantics."""
    _cached_linear_implication.cache_clear()
