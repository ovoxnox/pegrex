from pegrex.repairloop import repair_and_recheck


def analyzer(path):
    from pathlib import Path
    source = Path(path).read_text()
    findings = []
    if "eval(" in source:
        findings.append({"id": "NO-EVAL", "function": "f", "line": 2, "kind": "taint"})
    if "system(" in source:
        findings.append({"id": "NO-SYSTEM", "function": "f", "line": 2, "kind": "taint"})
    return {"status": "ok", "findings": findings, "unknowns": []}


def test_repair_recompares_same_analysis_before_applying(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("def f(x):\n    return eval(x)\n")
    result = repair_and_recheck(target, {"id": "NO-EVAL"},
        lambda current, finding, feedback: current.replace("eval(x)", "x"),
        analyzer=analyzer, project_root=tmp_path, audit_dir=tmp_path / "audit")
    assert result["status"] == "repaired" and result["applied"]
    assert "eval(" not in target.read_text()
    assert result["after"]["findings"] == []


def test_new_or_increased_finding_rejects_candidate_without_edit(tmp_path):
    target = tmp_path / "app.py"
    original = "def f(x):\n    return eval(x)\n"
    target.write_text(original)
    result = repair_and_recheck(target, {"id": "NO-EVAL"},
        lambda current, finding, feedback: "def f(x):\n    return system(x)\n",
        analyzer=analyzer, project_root=tmp_path, audit_dir=tmp_path / "audit")
    assert result["status"] == "unresolved" and not result["applied"]
    assert result["unchanged"]
    check = result["trail"][0]["gate"]["candidate_check"]
    assert check["new_or_increased_findings"][0]["id"] == "NO-SYSTEM"


def test_failed_candidate_feedback_can_drive_next_round(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("def f(x):\n    return eval(x)\n")
    def generate(current, finding, feedback):
        if feedback is None:
            return current  # finding remains
        return current.replace("eval(x)", "x")
    result = repair_and_recheck(target, {"id": "NO-EVAL"}, generate,
        analyzer=analyzer, project_root=tmp_path, audit_dir=tmp_path / "audit", max_rounds=2)
    assert result["status"] == "repaired"
    assert result["rounds"] == 2
