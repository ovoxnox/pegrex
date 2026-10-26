from pegrex.core.contracts import subsume
from pegrex.core.models import PathContract


def row(constraints, outcome, **kwargs):
    return PathContract.create(constraints, outcome, **kwargs)


def test_semantic_subsumption_uses_implication_not_just_syntactic_subsets():
    broad = row(["x >= 0"], "x + 0")
    narrow = row(["x >= 1", "2*x <= 8"], "x")
    report = subsume([narrow, broad], semantic=True)
    assert len(report["kept"]) == 1
    assert report["kept"][0]["outcome"] == "x + 0"
    assert report["removed"][0]["reason"].endswith("QF_LIA guard implication")


def test_different_observable_effects_are_not_subsumed():
    pure = row(["x >= 0"], "x", metadata=(("effects", "none"),))
    writes = row(["x >= 1"], "x", metadata=(("effects", "filesystem"),))
    report = subsume([pure, writes], semantic=True)
    assert len(report["kept"]) == 2


def test_unknown_subsumption_keeps_both_paths_and_reports_coverage():
    first = row(["f(x) > 0"], "x")
    second = row(["f(x) >= 0"], "x")
    report = subsume([first, second], semantic=True)
    assert len(report["kept"]) == 2
    assert report["unknowns"]


def test_legacy_syntactic_mode_remains_available():
    report = subsume([row(["x >= 0"], "x"), row(["x >= 0", "x < 2"], "x")])
    assert report["method"] == "syntactic-only; same-outcome required"
    assert len(report["kept"]) == 1
