import json
from pathlib import Path

import pytest

from pegrex.semantics import explain_patch, semantic_diff, verify_patch

ROOT = Path(__file__).parent / "golden" / "semantic_diff"
CASES = json.loads((ROOT / "manifest.json").read_text())["cases"]


@pytest.mark.parametrize("case", CASES)
def test_golden_semantic_diff_corpus(case):
    directory = ROOT / case
    before = directory / "before.py"
    after = directory / "after.py"
    expected = json.loads((directory / "expected.json").read_text())
    diff = semantic_diff(str(before), str(after))
    assert diff["identical"] is expected["identical"], diff
    verification = verify_patch(str(before), str(after))
    assert bool(verification.get("counterexample")) is expected["confirmed_witness"]
    explanation = explain_patch(str(before), str(after))
    assert explanation["schema"] == "pegrex.patch-explanation.v1"
    assert explanation["verdict"] == expected["explanation_verdict"], explanation
    if expected.get("effect_change"):
        assert any(row["kind"] == "effects" for row in explanation["changes"])
