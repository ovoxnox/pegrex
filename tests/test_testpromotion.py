import os
from pathlib import Path
import subprocess
import sys

import pytest

from pegrex.semantics import verify_patch
from pegrex.testpromotion import promote_counterexample, promote_patch_counterexample


def test_unconfirmed_or_unevaluated_counterexample_is_not_promoted(tmp_path):
    with pytest.raises(ValueError, match="expected is required"):
        promote_counterexample({"inputs": {"x": 1}, "confirmed": True},
                               "f", tmp_path / "test_x.py")
    with pytest.raises(ValueError, match="unconfirmed"):
        promote_counterexample({"inputs": {"x": 1}}, "f", tmp_path / "test_x.py",
                               expected=1)
    with pytest.raises(ValueError, match="unconfirmed"):
        promote_counterexample({"inputs": {"x": 1}, "confirmed": False},
                               "f", tmp_path / "test_x.py", expected=1)


def test_expected_counterexample_promotion_is_idempotent_and_runnable(tmp_path):
    (tmp_path / "fixture_module.py").write_text("def f(x):\n    return x + 1\n")
    output = tmp_path / "test_promoted.py"
    first = promote_counterexample({"inputs": {"x": 2}, "confirmed": True}, "f", output,
                                   expected=3, module="fixture_module")
    second = promote_counterexample({"inputs": {"x": 2}, "confirmed": True}, "f", output,
                                    expected=3, module="fixture_module")
    assert first["status"] == "created" and second["status"] == "existing"
    env = dict(os.environ, PYTHONPATH=str(tmp_path))
    completed = subprocess.run([sys.executable, "-m", "pytest", "-q", str(output)],
                               env=env, capture_output=True, text=True, timeout=30)
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_patch_counterexample_becomes_differential_regression(tmp_path):
    before = tmp_path / "before.py"
    after = tmp_path / "after.py"
    before.write_text("def f(x):\n    if x >= 0:\n        return x + 1\n    return 0\n")
    after.write_text("def f(x):\n    if x >= 0:\n        return x + 2\n    return 0\n")
    result = verify_patch(str(before), str(after))
    assert result["counterexample"]["confirmed"] is True
    output = tmp_path / "test_diff.py"
    promoted = promote_patch_counterexample(result["counterexample"], "f",
                                            before, after, output)
    assert promoted["status"] == "created"
    failed = subprocess.run([sys.executable, "-m", "pytest", "-q", str(output)],
                            capture_output=True, text=True, timeout=30)
    assert failed.returncode == 1
    after.write_text(before.read_text())
    fixed = subprocess.run([sys.executable, "-m", "pytest", "-q", str(output)],
                           capture_output=True, text=True, timeout=30)
    assert fixed.returncode == 0, fixed.stdout + fixed.stderr
