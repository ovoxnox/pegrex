from pathlib import Path

from pegrex.workers import analyze_source_isolated, compile_grammar_isolated


def test_analyzer_worker_parses_without_executing_source(tmp_path):
    marker = tmp_path / "executed"
    source = f"from pathlib import Path\nPath({str(marker)!r}).write_text('bad')\n\ndef f(x):\n    return x\n"
    result = analyze_source_isolated(source, analysis="ssa")
    assert result["status"] == "ok"
    assert result["result"]["functions"][0]["name"] == "f"
    assert result["worker"]["source_executed"] is False
    assert not marker.exists()


def test_worker_analysis_failure_is_unknown_not_clean():
    result = analyze_source_isolated("def broken(:", analysis="effects")
    assert result["status"] == "unknown"
    assert result["result"] is None
    assert result["unknowns"][0]["reason"] == "worker-analysis-failed"


def test_grammar_compiles_in_worker_and_bad_grammar_is_unknown():
    result = compile_grammar_isolated("start <- 'a' !.")
    assert result["status"] == "ok"
    assert result["result"]["rules"]
    failed = compile_grammar_isolated("start <- (")
    assert failed["status"] == "unknown"


def test_worker_refuses_oversized_input():
    result = analyze_source_isolated("x" * 2_000_001)
    assert result["status"] == "unknown"
    assert result["unknowns"][0]["reason"] == "input-limit-exceeded"
