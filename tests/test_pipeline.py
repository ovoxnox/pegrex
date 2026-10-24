import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
import pipeline


def test_fact_spec():
    results = pipeline.run_spec("specs/fact.json")
    assert results["python"] == results["c"]
    assert len(results["python"]) == 2
