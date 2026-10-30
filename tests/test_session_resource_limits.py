"""Regression tests for explicit analysis-session resource outcomes."""
from pegrex.sessions import AnalysisSession


def test_source_byte_limit_is_unknown_not_an_exception():
    report = AnalysisSession("x = 1\n", max_source_bytes=2).analyze(("contracts",))
    result = report["results"]["contracts"]
    assert result["status"] == "unknown"
    assert result["resource"] == "input-or-analysis-size-cap"
    assert "source exceeds input budget" in result["reason"]


def test_output_limit_is_unknown_not_truncated_success():
    report = AnalysisSession("x = 1\n", max_output_bytes=1).analyze(("complexity",))
    result = report["results"]["complexity"]
    assert result["status"] == "unknown"
    assert result["resource"] == "output-size-cap"


def test_invalid_limits_are_rejected():
    try:
        AnalysisSession("x = 1", max_ast_nodes=0)
    except ValueError as error:
        assert "must be positive" in str(error)
    else:
        raise AssertionError("zero node budget must be rejected")


def test_tree_node_budget_is_unknown():
    source = "def f(x):\n    if x:\n        return 1\n    return 0\n"
    report = AnalysisSession(source, max_ast_nodes=1).analyze(("complexity",))
    result = report["results"]["complexity"]
    assert result["status"] == "unknown"
    assert result["resource"] == "input-or-analysis-size-cap"
    assert "syntax tree exceeds node budget" in result["reason"]
