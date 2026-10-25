import pathlib
import sys
import pytest

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import pipeline


def test_fact_spec():
    results = pipeline.run_spec("specs/fact.json")
    assert results["python"] == results["c"]
    assert len(results["python"]) == 2


def test_data_only_invariant_expression():
    assert pipeline._invariant_value('len(results["python"]) == 2', {"python": [1, 2]})


def test_invariant_never_executes_python(tmp_path):
    marker = tmp_path / "executed"
    payload = f"__import__('pathlib').Path({str(marker)!r}).write_text('bad')"
    with pytest.raises(ValueError, match="unsupported invariant syntax"):
        pipeline._invariant_value(payload, {})
    assert not marker.exists()
