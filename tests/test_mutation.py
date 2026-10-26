from __future__ import annotations

import sys

from pegrex.mutation import generate_mutants, mutation_test


SOURCE = """def f(x):
    if x > 0:
        return x + 1
    return 0
"""


def test_mutant_generation_is_deterministic_single_site_and_non_destructive():
    first = generate_mutants(SOURCE)
    assert first == generate_mutants(SOURCE)
    assert {row["kind"] for row in first} == {"comparison", "binary", "constant"}
    assert all(row["source"] != SOURCE for row in first)
    assert all(row["source_sha256"] == first[0]["source_sha256"] for row in first)


def test_mutation_score_counts_only_confirmed_behavior_changes(tmp_path):
    target = tmp_path / "module.py"
    target.write_text(SOURCE)
    # The arithmetic mutation is detected; comparison/constant mutations that
    # preserve this single tested observation survive and remain visible.
    (tmp_path / "test_module.py").write_text(
        "from module import f\n\ndef test_positive():\n    assert f(2) == 3\n")
    report = mutation_test(tmp_path, "module.py",
                           test_command=(sys.executable, "-m", "pytest", "-q"),
                           timeout_ms=30_000)
    assert report["baseline"]["returncode"] == 0
    assert report["killed"] >= 1
    assert report["survived"] >= 1
    assert report["mutation_score"] == report["killed"] / report["scored"]
    assert all(row.get("counterexample", {}).get("confirmed") is True
               for row in report["mutants"] if row["status"] in {"killed", "survived"})
    assert target.read_text() == SOURCE


def test_failing_baseline_invalidates_mutation_score(tmp_path):
    (tmp_path / "module.py").write_text("def f(x):\n    return x + 1\n")
    (tmp_path / "test_module.py").write_text(
        "from module import f\n\ndef test_wrong():\n    assert f(1) == 3\n")
    report = mutation_test(tmp_path, "module.py")
    assert report["status"] == "unknown"
    assert report["mutation_score"] is None
    assert report["mutants"] == []
    assert "baseline" in report["unknowns"][0]
