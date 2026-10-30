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

from ..limits import MAX_SOURCE_BYTES

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
        if not isinstance(self.text, str):
            raise TypeError("source text must be a string")
        source_bytes = self.text.encode("utf-8")
        if len(source_bytes) > MAX_SOURCE_BYTES:
            raise ValueError(
                f"source input exceeds {MAX_SOURCE_BYTES} UTF-8 bytes")
        from ..languages import normalize_language
        language = normalize_language(self.language)
        if language is None:
            raise ValueError(f"unsupported source language {self.language!r}")
        object.__setattr__(self, "language", language)
        actual_sha256 = hashlib.sha256(source_bytes).hexdigest()
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
        # Bound the read itself, not just a preceding stat: the file may grow
        # between metadata inspection and reading.
        with p.open("rb") as stream:
            raw = stream.read(MAX_SOURCE_BYTES + 1)
        if len(raw) > MAX_SOURCE_BYTES:
            raise ValueError(
                f"source input exceeds {MAX_SOURCE_BYTES} UTF-8 bytes: {p}")
        text = raw.decode("utf-8")
        return cls(text, lang, str(p.resolve()))

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

    def __post_init__(self) -> None:
        """Normalize direct construction as strictly as the factory path."""
        if isinstance(self.constraints, (str, bytes)):
            raise TypeError("constraints must be an iterable of constraint strings, not a scalar string")
        normalized = {" ".join(str(item).strip().split()) for item in self.constraints}
        object.__setattr__(self, "constraints", tuple(sorted(normalized)))
        if not isinstance(self.outcome, str):
            object.__setattr__(self, "outcome", str(self.outcome))
        if self.function is not None and not isinstance(self.function, str):
            object.__setattr__(self, "function", str(self.function))
        if self.source_hash is not None and not isinstance(self.source_hash, str):
            object.__setattr__(self, "source_hash", str(self.source_hash))
        metadata = self.metadata
        if isinstance(metadata, dict):
            items = metadata.items()
        else:
            try:
                items = list(metadata)
            except TypeError as error:
                raise TypeError("metadata must be a mapping or iterable of key/value pairs") from error
        try:
            pairs = {str(key): str(value) for key, value in items}
        except (TypeError, ValueError) as error:
            raise ValueError("metadata must contain key/value pairs") from error
        object.__setattr__(self, "metadata", tuple(sorted(pairs.items())))

    @classmethod
    def create(cls, constraints: Iterable[Any], outcome: Any, **kwargs) -> "PathContract":
        # Keep the original normalized surface text in the public field. Older
        # APIs expose these strings, so canonical hashes do not force clients
        # to migrate to solver-internal notation such as ``1*n`` coefficients.
        if isinstance(constraints, (str, bytes)):
            raise TypeError("constraints must be an iterable of constraint strings, not a scalar string")
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
