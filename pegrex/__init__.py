"""pegrex -- self-contained PEG engine, symbolic analyzer, and AI spec generator."""
import pathlib as _pl
import sys as _sys

#_vend = _pl.Path(__file__).parent.parent / ".vendor" / "py"
#if _vend.exists() and str(_vend) not in _sys.path:
#    _sys.path.insert(0, str(_vend))   # vendored tree-sitter bindings

from .compiler import compile_grammar, calcline, prettyast, GrammarError
from .peg import Node, run, Throw
__all__ = ["compile_grammar", "calcline", "prettyast", "GrammarError", "Node", "run", "Throw"]
