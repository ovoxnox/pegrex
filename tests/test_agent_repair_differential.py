import hashlib
from pathlib import Path

import pegrex.repairloop as repairloop
from pegrex.repairloop import repair_with_sandboxed_differential, sandboxed_differential


def analyzer(path):
    source = Path(path).read_text()
    findings = []
    if "eval(" in source:
        findings.append({"id": "NO-EVAL", "function": "f", "kind": "taint"})
    if "system(" in source:
        findings.append({"id": "NO-SYSTEM", "function": "f", "kind": "taint"})
    return {"status": "ok", "findings": findings, "unknowns": []}


def fake_sandbox(monkeypatch, behavior_change=False):
    monkeypatch.setattr(repairloop, "sandbox_status", lambda: {
        "available": True, "backend": "test-double", "unknowns": []})

    def execute(argv, *, files=None, timeout_ms=5000, memory_mb=256):
        source = files["app.py"]
        evidence = "changed" if behavior_change and b"return x" in source else "same"
        return {"status": "reproduced", "executed": True, "confirmed": True,
                "returncode": 0, "evidence": evidence, "unknowns": [],
                "sandbox": {"ephemeral": True, "isolated": True,
                            "no_credentials": True, "no_network": True}}

    monkeypatch.setattr(repairloop, "run_poc", execute)


def independent(before, after):
    return {"verdict": "proved", "proof": {
        "before_sha256": hashlib.sha256(Path(before).read_bytes()).hexdigest(),
        "after_sha256": hashlib.sha256(Path(after).read_bytes()).hexdigest()}}


def repair(target, monkeypatch, checker=independent):
    return repair_with_sandboxed_differential(
        target, {"id": "NO-EVAL"},
        lambda current, finding, feedback: current.replace("eval(x)", "x"),
        argv=["python", "harness.py"], files={"harness.py": "print('ok')"},
        independent_checker=checker, analyzer=analyzer,
        project_root=target.parent, audit_dir=target.parent / "audit")


def test_sandboxed_differential_is_bounded_evidence_not_equivalence_proof(tmp_path, monkeypatch):
    fake_sandbox(monkeypatch)
    before = tmp_path / "app.py"
    after = tmp_path / "after.py"
    before.write_text("def f(x):\n    return eval(x)\n")
    after.write_text("def f(x):\n    return x\n")
    report = sandboxed_differential(before, after, argv=["python", "harness.py"])
    assert report["status"] == "passed" and report["allowed"]
    assert report["verdict"] == "unknown"
    assert "bounded differential observations do not prove semantic equivalence" in report["unknowns"]


def test_agent_repair_requires_differential_and_independent_post_fix_proof(tmp_path, monkeypatch):
    fake_sandbox(monkeypatch)
    target = tmp_path / "app.py"
    target.write_text("def f(x):\n    return eval(x)\n")
    calls = []

    def checker(before, after):
        calls.append(after)
        return independent(before, after)

    result = repair(target, monkeypatch, checker)
    assert result["status"] == "repaired" and result["applied"]
    assert result["post_fix_status"] == "proved" and result["exact_candidate_applied"]
    assert len(calls) == 2 and Path(calls[-1]) == target
    additional = result["trail"][0]["gate"]["candidate_check"]["additional_validation"]
    assert additional["differential"]["status"] == "passed"
    assert additional["independent"]["verdict"] == "proved"
    assert "eval(" not in target.read_text()


def test_behavioral_differential_counterexample_rejects_without_edit(tmp_path, monkeypatch):
    fake_sandbox(monkeypatch, behavior_change=True)
    target = tmp_path / "app.py"
    original = "def f(x):\n    return eval(x)\n"
    target.write_text(original)
    result = repair(target, monkeypatch)
    assert not result["applied"] and result["unchanged"]
    assert target.read_text() == original
    additional = result["trail"][0]["gate"]["candidate_check"]["additional_validation"]
    assert additional["differential"]["verdict"] == "refuted"
    assert additional["differential"]["counterexample"]["confirmed"]


def test_post_fix_unknown_restores_original_and_preserves_attempt_evidence(tmp_path, monkeypatch):
    fake_sandbox(monkeypatch)
    target = tmp_path / "app.py"
    original = "def f(x):\n    return eval(x)\n"
    target.write_text(original)
    calls = []

    def flaky_checker(before, after):
        calls.append(after)
        if len(calls) == 1:
            return independent(before, after)
        return {"verdict": "unknown", "unknowns": ["independent post-fix solver unavailable"]}

    result = repair(target, monkeypatch, flaky_checker)
    assert result["status"] == "unknown" and not result["applied"]
    assert result["rolled_back"] and result["unchanged"]
    assert target.read_text() == original
    attempt_id = result["audit_attempt_id"]
    assert (tmp_path / "audit" / attempt_id / "proposed.txt").read_text() != original
    assert result["trail"][-1]["status"] == "post-fix-validation-not-proved"


def test_unavailable_sandbox_refuses_before_generating_a_candidate(tmp_path, monkeypatch):
    monkeypatch.setattr(repairloop, "sandbox_status", lambda: {
        "available": False, "unknowns": ["sandbox unavailable"]})
    target = tmp_path / "app.py"
    original = "def f(x):\n    return eval(x)\n"
    target.write_text(original)
    called = []
    result = repair_with_sandboxed_differential(
        target, {"id": "NO-EVAL"}, lambda *args: called.append(args),
        argv=["python", "harness.py"], independent_checker=independent,
        analyzer=analyzer, project_root=tmp_path)
    assert result["status"] == "unknown" and not result["applied"]
    assert result["unchanged"] and target.read_text() == original
    assert called == []
