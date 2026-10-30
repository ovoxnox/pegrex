import pytest
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent


def test_m9_trifecta_certificate():
    pytest.importorskip("tree_sitter", reason="M9 cross-language certificate requires optional parser dependencies")
    r = subprocess.run([sys.executable, "certs/m9_trifecta.py"], cwd=ROOT,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "M9 CERTIFICATE" in r.stdout
    assert "'negated-return'" in r.stdout      # go rule fired
    assert "'explicit-return'" in r.stdout     # rust rule fired
    assert "'eq-none-anti-pattern'" not in r.stdout.split("M9")[0].split("[python")[-1]


def test_go_for_clause_parts():
    sys.path.insert(0, str(ROOT))
    from pegrex.tree_sitter_bridge import TAGSPECS
    from pegrex.peg import Node

    class FakeTS:
        def __init__(self, type_, children=(), s=0, e=0):
            self.type, self.children = type_, list(children)
            self.is_named, self.start_byte, self.end_byte = True, s, e
            self.child_count = len(self.children)

    from pegrex.tree_sitter_bridge import ts_to_pegrex
    cst = FakeTS("for_statement", [
        FakeTS("for_clause", [
            FakeTS("short_var_declaration", [FakeTS("identifier", s=5, e=6)], s=5, e=11),
            FakeTS("binary_expression", s=14, e=19),
            FakeTS("inc_statement", [FakeTS("identifier", s=22, e=23)], s=22, e=27),
        ]),
        FakeTS("block", [], s=29, e=31),
    ])
    tree = ts_to_pegrex(cst, "for i := 0; i < n; i++ {}")
    fn = TAGSPECS["go"].while_
    kids = [c for c in tree.children]
    cond, body = fn(kids)
    assert cond.tag == "binary_expression"
    assert body.tag == "block"
