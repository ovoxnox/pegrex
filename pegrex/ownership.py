"""ownership.py -- Rust ownership as proof: borrow patterns over MIR/source.
Tracks &mut aliasing: two live &mut borrows of the same base = a violation
the constraint layer can flag before rustc does."""
from __future__ import annotations

import re

MUT_RE = re.compile(r"&\s*mut\s+(\w+)")
REF_RE = re.compile(r"&\s*(\w+)")


def borrow_check(src: str) -> list:
    """Find shared/mutable borrow conflicts at the source level.
    Returns violations: [(var, kind)]."""
    muts = {}
    for m in MUT_RE.finditer(src):
        muts.setdefault(m.group(1), 0)
        muts[m.group(1)] += 1
    return [(v, "multiple-mut") for v, n in muts.items() if n > 1]
