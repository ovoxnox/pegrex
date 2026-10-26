"""Generated HEALTH report must match exact findings and dispositions."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _module():
    spec = importlib.util.spec_from_file_location(
        "health_report_test", ROOT / "tools" / "health_report.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_health_report_is_fresh_and_complete():
    result = subprocess.run(
        [sys.executable, "tools/health_report.py", "--check"], cwd=ROOT,
        capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
    spec, dispositions, digest = _module().load_validated()
    assert set(dispositions["tasks"]) == {task["id"] for task in spec["tasks"]}
    assert digest == hashlib.sha256(
        (ROOT / "specs" / "pegrex_health.spec.json").read_bytes()).hexdigest()


def test_health_dispositions_reject_stale_report(tmp_path):
    module = _module()
    spec = {"tasks": [{"id": "T1", "severity": "LOW", "view": "testing",
                       "title": "evidence"}]}
    dispositions = {
        "schema": module.SCHEMA,
        "report_sha256": "0" * 64,
        "policies": {"maintenance": {"status": "maintenance-open",
                                      "rationale": "test evidence",
                                      "evidence": ["test"]}},
        "tasks": {"T1": "maintenance"},
    }
    with pytest.raises(ValueError, match="stale"):
        module._validate(spec, dispositions, "f" * 64)


def test_health_dispositions_reject_missing_task():
    module = _module()
    spec = {"tasks": [{"id": "T1"}, {"id": "T2"}]}
    dispositions = {
        "schema": module.SCHEMA,
        "report_sha256": "a" * 64,
        "policies": {"maintenance": {"status": "maintenance-open",
                                      "rationale": "test evidence",
                                      "evidence": ["test"]}},
        "tasks": {"T1": "maintenance"},
    }
    with pytest.raises(ValueError, match="missing=.*T2"):
        module._validate(spec, dispositions, "a" * 64)
