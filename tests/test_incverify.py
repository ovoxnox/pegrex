import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import pytest

from pegrex.cache import AnalysisCache
from pegrex.incverify import IncverifyError, verify_patch_incremental

BEFORE = """\
def clamp(x):
    if x < 0:
        return 0
    return x

def ident(y):
    return y
"""


@pytest.fixture
def pair(tmp_path):
    b = tmp_path / "before.py"
    a = tmp_path / "after.py"
    b.write_text(BEFORE)
    a.write_text(BEFORE)
    return b, a, AnalysisCache(tmp_path / "cache")


def test_identical_files_prove_free(pair):
    b, a, cache = pair
    r = verify_patch_incremental(b, a, cache=cache)
    assert r["verdict"] == "proved"
    assert r["reused"] == 2 and r["reverified"] == 0


def test_only_changed_function_reverified(pair):
    b, a, cache = pair
    a.write_text(BEFORE.replace("if x < 0:", "if x <= -1:"))
    r = verify_patch_incremental(b, a, cache=cache)
    assert r["reused"] == 1
    assert r["per_function"]["ident"]["verdict"] == "identical"
    assert r["per_function"]["clamp"]["verdict"] == "engine"


def test_semantic_break_counterexample_names_function(pair):
    b, a, cache = pair
    a.write_text(BEFORE.replace("return 0\n", "return x\n", 1))
    r = verify_patch_incremental(b, a, cache=cache)
    assert r["verdict"] == "counterexample"
    assert r["per_function"]["clamp"]["verified"] is False
    assert any(d["function"] == "clamp" for d in r["distinguishing"])


def test_removed_function_is_counterexample(pair):
    b, a, cache = pair
    a.write_text("def clamp(x):\n    if x < 0:\n        return 0\n    return x\n")
    r = verify_patch_incremental(b, a, cache=cache)
    assert r["verdict"] == "counterexample"
    assert r["per_function"]["ident"]["verdict"] == "removed"


def test_verdict_caches_across_runs(pair):
    b, a, cache = pair
    a.write_text(BEFORE.replace("if x < 0:", "if x <= -1:"))
    r1 = verify_patch_incremental(b, a, cache=cache)
    r2 = verify_patch_incremental(b, a, cache=cache)
    assert r1["verdict"] == r2["verdict"]
    if r1["per_function"]["clamp"]["verified"]:
        assert r2["cache_hits"] >= 1
        assert r2["per_function"]["clamp"]["verdict"] == "cached"


def test_corrupt_cache_rebuilt_not_crashed(pair, tmp_path):
    b, a, cache = pair
    key = cache.key("poison", ("verify-patch",))
    key.write_text("{not json")
    a.write_text(BEFORE.replace("if x < 0:", "if x <= -1:"))
    r = verify_patch_incremental(b, a, cache=cache)
    assert r["verdict"] in ("proved", "counterexample")


def test_syntax_error_refuses(pair):
    b, a, cache = pair
    b.write_text("def broken(:\n")
    with pytest.raises(IncverifyError, match="before.py"):
        verify_patch_incremental(b, a, cache=cache)


def test_missing_file_refuses(tmp_path):
    with pytest.raises(IncverifyError, match="no such file"):
        verify_patch_incremental(tmp_path / "nope.py", tmp_path / "nope2.py")
