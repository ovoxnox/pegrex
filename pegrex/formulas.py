"""formulas.py -- compatibility shim.  The symbolic core lives in
pegrex.sym; path formulas in pegrex.paths.  This module re-exports both so
legacy imports keep working; new code should import from sym/paths directly.
"""
from .sym import *
from .paths import *
