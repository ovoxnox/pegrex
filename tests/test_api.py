import pathlib

from pegrex import api

ROOT = pathlib.Path(__file__).parent.parent


def test_api_surface():
    assert api.contracts(str(ROOT / "specs" / "fact.py")) == [
        (frozenset({"(n = 0)"}), "1"),
        (frozenset({"(not (n = 0))"}), "n * fact(n - 1)")]
    b = api.budget_check(str(ROOT / "pegrex" / "lpegc" / "compiler.py"))  # post-split core
    assert not b.passed and b.findings
    idx = api.rag_index([str(ROOT / "specs")])
    assert any("fact" in h.source for h in api.rag_search(idx, "def fact", 2))
    mir = ("fn f(_1: i32) -> i32 {\n    bb0: {\n        _0 = _1;\n"
           "        return;\n    }\n}\n")
    assert len(api.mir_cfg(mir).blocks) == 1
    bundle = api.bundle(str(ROOT / "specs" / "fact.py"))
    assert len(bundle["paths"]) == 2 and bundle["smt2"]
