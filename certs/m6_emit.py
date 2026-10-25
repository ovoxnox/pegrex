#!/usr/bin/env python
"""M6: guarded idiom emission and its negative cross-language control."""
import json
import pathlib
import subprocess
import sys
ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pipeline
from pegrex.cfg import CFGBuilder
from pegrex.idioms import IdiomRule, translate

src = (ROOT / "specs/fact.py").read_text()
parse, tagspec, make_cond = pipeline.python_frontend()
body = parse(src)
constraints = pipeline.path_constraints(CFGBuilder(tagspec).build(body), make_cond(src), 1)
rule = IdiomRule("ternary", ["if_statement"], "return {c} ? {t} : {e};",
                 path_guard="(= n 0)", slots={"c": 0, "t": 1, "e": 2})
emitted = translate(body, [rule], constraints, src=src)
expected = "return n == 0 ? 1 : n * fact(n - 1);"
assert emitted == [("ternary", expected)], emitted
assert expected in (ROOT / "specs/fact_ternary.c").read_text()
negative = subprocess.run([sys.executable, "pipeline.py", "specs/fact_negative.json"],
                          cwd=ROOT, capture_output=True, text=True)
assert negative.returncode != 0
assert "invariant violated" in negative.stderr or "mismatch" in negative.stderr
print(f"M6 CERTIFICATE: {expected}; negative control rejected")
