#!/usr/bin/env python
"""M9: structural rules across Python, Go, and Rust with a Python negative control."""
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pegrex.patterns import Pattern, scan
from pegrex.tree_sitter_bridge import parse

CASES = {
    "python": ("def f(value):\n    return value\n",
               [Pattern(node_type="comparison_operator", text=r"==\s*None",
                        id="eq-none-anti-pattern")], []),
    "go": ("package p\nfunc f(n int) int { if n < 0 { return -n }; return n }\n",
           [Pattern(node_type="return_statement", text=r"return\s+-",
                    id="negated-return")], ["negated-return"]),
    "rust": ("fn f(n: i32) -> i32 { if n < 0 { return -n; } n }\n",
             [Pattern(node_type="return_expression", text=r"return\s+-",
                      id="explicit-return")], ["explicit-return"]),
}
for language, (source, rules, expected) in CASES.items():
    found = sorted({rule.id for _, rule, _ in scan(parse(language, source), rules, source)})
    assert found == expected, (language, found)
    print(f"[{language}] findings: {found}")
print("M9 CERTIFICATE: multilingual structural checks and negative control passed")
