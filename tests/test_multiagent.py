from pathlib import Path

from pegrex.editaudit import EditAudit
from pegrex.multiagent import ROLE_SCHEMA, SCHEMA, run_multi_agent_change


ORIGINAL = """def f(x):
    if x >= 0:
        return x + 1
    return 0
"""


def test_four_roles_feed_proof_gate_and_apply_equivalent_patch(tmp_path):
    target = tmp_path / "app.py"
    target.write_text(ORIGINAL)
    calls = []
    def candidates(source, finding):
        calls.append("candidate")
        return {"operation": "format", "finding": finding}
    def patch(source, candidate, finding):
        calls.append("patch")
        return source.replace("x + 1", "(x + 1)")
    result = run_multi_agent_change(target, candidates, patch,
        finding={"rule_id": "style"}, audit_dir=tmp_path / "audit")
    assert result["schema"] == SCHEMA and result["applied"]
    assert [row["role"] for row in result["roles"]] == [
        "candidate-generation", "patch-generation", "counterexample-search",
        "independent-checking"]
    assert all(row["schema"] == ROLE_SCHEMA for row in result["roles"])
    assert result["roles"][-1]["data"]["kernel"]["checked"]
    assert result["patch_gate"]["candidate_check"]["allowed"]
    assert calls == ["candidate", "patch"]
    assert target.read_text() != ORIGINAL


def test_counterexample_role_rejects_behavior_change_without_target_mutation(tmp_path):
    target = tmp_path / "app.py"
    target.write_text(ORIGINAL)
    result = run_multi_agent_change(target, lambda source, finding: {"repair": "bad"},
        lambda source, candidate, finding: source.replace("x + 1", "x + 2"),
        audit_dir=tmp_path / "audit")
    assert not result["applied"] and result["verdict"] == "refuted"
    assert result["roles"][2]["data"]["confirmed"] is True
    assert result["roles"][2]["data"]["counterexample"] is not None
    assert target.read_text() == ORIGINAL
    attempt = tmp_path / "audit" / result["patch_gate"]["audit_attempt_id"]
    assert EditAudit.verify(attempt)["ok"]


def test_generator_cannot_be_its_own_independent_checker(tmp_path):
    target = tmp_path / "app.py"
    target.write_text(ORIGINAL)
    def generator(source, candidate=None, finding=None):
        return source if candidate is None else source.replace("x + 1", "(x + 1)")
    result = run_multi_agent_change(target, lambda source, finding: {"change": True},
        generator, independent_checker=generator, audit_dir=tmp_path / "audit")
    assert not result["applied"]
    assert result["roles"][-1]["verdict"] == "unknown"
    assert "checker-must-be-independent-of-generators" in result["unknowns"]
    assert result["patch_gate"]["candidate_check"]["allowed"] is False
    assert target.read_text() == ORIGINAL


def test_generation_failure_is_unknown_and_never_reaches_patch_stage(tmp_path):
    target = tmp_path / "app.py"
    target.write_text(ORIGINAL)
    called = []
    result = run_multi_agent_change(target, lambda source, finding: None,
        lambda *args: called.append(args), audit_dir=tmp_path / "audit")
    assert result["status"] == "rejected" and result["verdict"] == "unknown"
    assert not called and target.read_text() == ORIGINAL
