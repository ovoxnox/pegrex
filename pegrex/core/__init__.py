"""PegRex stable core.

The core is the supported dependency boundary for source documents, language
capabilities, normalized path contracts, operation results, and orchestration.
Feature modules remain optional adapters and should not become dependencies of
core data models.
"""
from .models import (SCHEMA_VERSION, OperationResult, OperationStatus,
                     PathContract, SourceDocument, Verdict, contracts_from_pairs)
from .contracts import as_legacy_pairs, canonicalize, subsume
from .engine import CapabilityError, CoreEngine, get_engine

__all__ = [
    "SCHEMA_VERSION", "OperationResult", "OperationStatus", "PathContract",
    "SourceDocument", "Verdict", "contracts_from_pairs", "as_legacy_pairs",
    "canonicalize", "subsume", "CapabilityError", "CoreEngine", "get_engine",
]
