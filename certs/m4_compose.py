#!/usr/bin/env python
"""M4: function contracts compose without losing guards or precedence."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pegrex.summaries import compose

caller = [(frozenset(), "clamp(n) + 1")]
callee = [(frozenset({"(x < 0)"}), "0"),
          (frozenset({"(not (x < 0))"}), "x")]
out = compose(caller, "clamp", callee, param="x", arg="n")
assert out == [(frozenset({"(n < 0)"}), "0 + 1"),
               (frozenset({"(not (n < 0))"}), "n + 1")], out
unchanged = [(frozenset({"(n = 0)"}), "1")]
assert compose(unchanged, "clamp", callee, "x", "n") == unchanged
print("M4 CERTIFICATE: guarded composition and no-call negative control passed")
