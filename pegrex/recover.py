"""recover.py -- error-tolerant parsing: on failure, skip to the next line,
record the error, continue.  Partial files still produce ASTs + findings."""
from __future__ import annotations


def run_recovering(patt, source: str, rules=None) -> tuple:
    """Parse with line-level recovery. Returns (value, errors) where errors
    is a list of (label, pos); unmatched lines are skipped."""
    from . import peg
    errors = []
    pos = 0
    value = None
    while pos <= len(source):
        v, err, errpos = peg.run(patt, source[pos:], rules)
        if err is None:
            value = v
            break
        errors.append((err, pos + (errpos or 0)))
        nl = source.find(chr(10), pos + 1)
        if nl < 0:
            break
        pos = nl + 1
    return value, errors
