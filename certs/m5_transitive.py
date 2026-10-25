#!/usr/bin/env python
"""M5: transitive call expansion reaches a fixed point with path guards."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pegrex.summaries import expand_calls

clamp = [(frozenset({"(x < 0)"}), "0"),
         (frozenset({"(not (x < 0))"}), "x")]
clamp1 = expand_calls([(frozenset(), "clamp(y) + 1")],
                      {"clamp": clamp}, {"clamp": "x"})
entry = expand_calls([(frozenset(), "clamp1(n) * 2")],
                     {"clamp": clamp, "clamp1": clamp1},
                     {"clamp": "x", "clamp1": "y"})
assert sorted(result for _, result in entry) == ["(0 + 1) * 2", "(n + 1) * 2"], entry
assert len(entry) == 2
print("M5 CERTIFICATE: transitive contracts preserve both path outcomes")
