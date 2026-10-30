"""pegrex -- self-contained PEG engine, symbolic analyzer, and AI spec generator."""
import pathlib as _pl
import sys as _sys

#_vend = _pl.Path(__file__).parent.parent / ".vendor" / "py"
#if _vend.exists() and str(_vend) not in _sys.path:
#    _sys.path.insert(0, str(_vend))   # vendored tree-sitter bindings

from .compiler import compile_grammar, calcline, prettyast, GrammarError
from .peg import Node, run, Throw
from .core import (CoreEngine, OperationResult, OperationStatus, PathContract,
                   SourceDocument, Verdict, get_engine)
from .languages import (language_capabilities, capability_matrix, detect_language,
                        frontend_manifest, parser_provenance, plugin_registry,
                        soundness_report)
from .sessions import AnalysisSession, AnalysisTimeout
from .pathcontract_v2 import validate_path_contract_v2

__version__ = "1.3.0"
__all__ = ["__version__","compile_grammar", "calcline", "prettyast", "GrammarError", "Node", "run", "Throw",
           "CoreEngine", "OperationResult", "OperationStatus", "PathContract",
           "SourceDocument", "Verdict", "get_engine", "language_capabilities",
           "capability_matrix", "detect_language", "frontend_manifest",
           "parser_provenance", "plugin_registry", "soundness_report",
           "AnalysisSession", "AnalysisTimeout", "validate_path_contract_v2"]

# Next-generation evidence workflows. These modules expose conservative APIs:
# heuristic scores prioritize work, observations do not prove unobserved paths,
# and composition reports evidence completeness rather than semantic truth.
from .immune import audit_repository
from .regressionnetwork import register_case, sanitize_case, minimize_case
from .observability import ingest_trace, compare_trace_revisions
from .buildgate import evaluate_release, write_release_attestation
from .hybridpriority import prioritize_paths
from .proofguidedfuzz import candidates_from_conditions, confirm_counterexample
from .composition import component_record, verify_composition

__all__ += [
    "audit_repository", "register_case", "sanitize_case", "minimize_case",
    "ingest_trace", "compare_trace_revisions", "evaluate_release",
    "write_release_attestation", "prioritize_paths", "candidates_from_conditions",
    "confirm_counterexample", "component_record", "verify_composition",
]
