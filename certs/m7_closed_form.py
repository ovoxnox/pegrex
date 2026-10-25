#!/usr/bin/env python
"""M7: loop invariant, ranking function, and closed form agree with execution."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pegrex.loopsum import summarize

SRC = """def sum_to(n):
    s = 0
    i = 1
    while i <= n:
        s = s + i
        i = i + 1
    return s
"""
result = summarize(SRC)
assert result["verdict"] == "proved", result
assert result["ranking"] == "n - i + 1"
closed = result["closed_form"]["result"]
assert closed == "((n * (n + 1)) // 2)", closed
namespace = {}
exec(SRC, namespace)
for n in (0, 1, 5, 42):
    assert namespace["sum_to"](n) == eval(closed, {"n": n})
print(f"M7 CERTIFICATE: {closed}; invariant and concrete executions agree")
