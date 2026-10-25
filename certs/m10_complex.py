#!/usr/bin/env python
"""M10: compound conditions and loop closed forms survive the combined pipeline."""
import pathlib
import sys
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pipeline
from pegrex.cfg import CFGBuilder
from pegrex.loopsum import summarize

source = "def f(n):\n    if n > 0 and n < 10:\n        return 1\n    return 0\n"
parse, tagspec, make_cond = pipeline.python_frontend()
cfg = CFGBuilder(tagspec).build(parse(source))
condition = make_cond(source)
texts = []
for _, edge in cfg.successors(0):
    base = edge.cond[0] if isinstance(edge.cond, tuple) else edge.cond
    if base is not None:
        texts.append(str(condition(base)))
assert any("and" in text for text in texts), texts
loop = summarize("""def sum_to(n):
    s = 0
    i = 1
    while i <= n:
        s = s + i
        i = i + 1
    return s
""")
closed = loop["closed_form"]["result"]
assert "(n * (n + 1))" in closed
assert loop["verdict"] == "proved"
print(f"M10 CERTIFICATE: compound guards preserved; closed form {closed}")
