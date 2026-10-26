"""Stable, dependency-light data models shared across PegRex features.

No parsers, solver backends, LLMs, or CLI modules are imported here. The core
is deliberately boring: immutable source coordinates, canonical contracts,
explicit operation status, and stable JSON serialization.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hashlib
import json
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = "pegrex.core.v1"


class Verdict(str, Enum):
    PROVED = "proved"
    REFUTED = "refuted"
    UNKNOWN = "unknown"


class OperationStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    ERROR = "error"


def canonical_json(value: Any) -> str:
    """Implement canonical json with the module's explicit API and failure semantics."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str)


def sha256_json(value: Any) -> str:
    """Implement sha256 json with the module's explicit API and failure semantics."""
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SourceDocument:
    text: str
    language: str
    path: str | None = None
    sha256: str = ""

    def __post_init__(self):
        from ..languages import normalize_language
        language = normalize_language(self.language)
        if language is None:
            raise ValueError(f"unsupported source language {self.language!r}")
        object.__setattr__(self, "language", language)
        actual_sha256 = hashlib.sha256(self.text.encode("utf-8")).hexdigest()
        if self.sha256 and self.sha256.lower() != actual_sha256:
            raise ValueError("source sha256 mismatch; refusing forged provenance")
        object.__setattr__(self, "sha256", actual_sha256)

    @classmethod
    def from_path(cls, path: str | Path, language: str | None = None) -> "SourceDocument":
        """Implement from path with the module's explicit API and failure semantics."""
        from ..languages import detect_language
        p = Path(path)
        lang = detect_language(p, language)
        if lang is None:
            raise ValueError(f"cannot detect language for {str(p)!r}")
        return cls(p.read_text(encoding="utf-8"), lang, str(p.resolve()))

    def slice(self, start: int, end: int) -> str:
        """Implement slice with the module's explicit API and failure semantics."""
        if not isinstance(start, int) or not isinstance(end, int):
            raise TypeError("source spans must use integer character offsets")
        if start < 0 or end < start or end > len(self.text):
            raise ValueError(f"invalid character span [{start}, {end}) for {len(self.text)} characters")
        return self.text[start:end]

    def line(self, offset: int) -> int:
        """Implement line with the module's explicit API and failure semantics."""
        self.slice(offset, offset)
        return self.text.count("\n", 0, offset) + 1

    def to_dict(self) -> dict[str, Any]:
        """Implement to dict with the module's explicit API and failure semantics."""
        return {"schema": SCHEMA_VERSION, "path": self.path, "language": self.language,
                "sha256": self.sha256, "characters": len(self.text),
                "utf8_bytes": len(self.text.encode("utf-8"))}


@dataclass(frozen=True)
class PathContract:
    constraints: tuple[str, ...]
    outcome: str
    function: str | None = None
    source_hash: str | None = None
    metadata: tuple[tuple[str, str], ...] = ()

    @classmethod
    def create(cls, constraints: Iterable[Any], outcome: Any, **kwargs) -> "PathContract":
        # Keep the original normalized surface text in the public field. Older
        # APIs expose these strings, so canonical hashes must not force clients
        # to migrate to solver-internal notation such as ``1*n`` coefficients.
        """Implement create with the module's explicit API and failure semantics."""
        normalized = {" ".join(str(constraint).strip().split())
                      for constraint in constraints}
        return cls(tuple(sorted(normalized)), str(outcome), **kwargs)

    @property
    def identity(self) -> str:
        # Keep the stable domain model independent from refinement/solver
        # modules. The core identity uses conservative surface normalization;
        # semantic equivalence belongs to an explicit analysis operation.
        """Implement identity with the module's explicit API and failure semantics."""
        canonical = [" ".join(constraint.split()) for constraint in self.constraints]
        return sha256_json({"constraints": sorted(canonical), "outcome": self.outcome,
                            "function": self.function, "source_hash": self.source_hash,
                            "metadata": self.metadata})

    def to_dict(self) -> dict[str, Any]:
        """Implement to dict with the module's explicit API and failure semantics."""
        return {"schema": SCHEMA_VERSION, "constraints": list(self.constraints),
                "outcome": self.outcome, "function": self.function,
                "source_hash": self.source_hash,
                "metadata": dict(self.metadata), "identity": self.identity}


@dataclass
class OperationResult:
    operation: str
    status: OperationStatus = OperationStatus.OK
    data: Any = None
    verdict: Verdict | None = None
    unknowns: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Implement to dict with the module's explicit API and failure semantics."""
        status = self.status.value if isinstance(self.status, OperationStatus) else str(self.status)
        verdict = self.verdict.value if isinstance(self.verdict, Verdict) else self.verdict
        return {"schema": SCHEMA_VERSION, "operation": self.operation, "status": status,
                "verdict": verdict, "data": self.data, "unknowns": list(self.unknowns),
                "assumptions": list(self.assumptions), "metadata": self.metadata}


def contracts_from_pairs(pairs: Iterable[tuple[Iterable[Any], Any]], *,
                         function: str | None = None,
                         source_hash: str | None = None) -> list[PathContract]:
    """Implement contracts from pairs with the module's explicit API and failure semantics."""
    rows = [PathContract.create(constraints, outcome, function=function,
                                source_hash=source_hash)
            for constraints, outcome in pairs]
    # Deduplicate by full observable contract identity, not guards alone.
    return sorted({row.identity: row for row in rows}.values(),
                  key=lambda row: (row.constraints, row.outcome, row.identity))
