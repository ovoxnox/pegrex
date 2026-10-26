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

__version__ = "1.1.0"
__all__ = ["__version__","compile_grammar", "calcline", "prettyast", "GrammarError", "Node", "run", "Throw",
           "CoreEngine", "OperationResult", "OperationStatus", "PathContract",
           "SourceDocument", "Verdict", "get_engine", "language_capabilities",
           "capability_matrix", "detect_language", "frontend_manifest",
           "parser_provenance", "plugin_registry", "soundness_report",
           "AnalysisSession", "AnalysisTimeout"]
