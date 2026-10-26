import json
import zipfile

from pegrex.actionbroker import (create_action_plan, authorize_action_plan,
    execute_action_plan, verify_action_evidence, revoke_action_authorization)
from pegrex.impact import simulate_change_impact
from pegrex.researchcapsule import create_research_capsule, verify_research_capsule
from pegrex.semanticchecksum import (semantic_checksum, diff_semantic_checksums,
    semantic_checksum_diff)


def test_semantic_checksum_ignores_surface_syntax_and_retains_assumptions(tmp_path):
    before, after = tmp_path / "before.py", tmp_path / "after.py"
    before.write_text("def f(x):\n    return x + 1\n")
    after.write_text("# comment only\ndef f(x):\n    return 1 + x\n")
    first = semantic_checksum(before, type_assumptions={"x": "int"},
                              domain_assumptions={"overflow": "unbounded"})
    second = semantic_checksum(after, type_assumptions={"x": "int"},
                               domain_assumptions={"overflow": "unbounded"})
    assert first["source_sha256"] != second["source_sha256"]
    assert first["semantic_checksum"] == second["semantic_checksum"]
    diff = diff_semantic_checksums(first, second)
    assert diff["identical"] and diff["verdict"] == "proved"
    assert "domain_assumptions" in first["payload"]


def test_semantic_checksum_mismatch_needs_confirmation_and_tamper_is_refuted(tmp_path):
    before, after = tmp_path / "before.py", tmp_path / "after.py"
    before.write_text("def f(x):\n    if x > 0:\n        return x\n    return 0\n")
    after.write_text("def f(x):\n    if x > 0:\n        return x + 1\n    return 0\n")
    first, second = semantic_checksum(before), semantic_checksum(after)
    diff = diff_semantic_checksums(first, second)
    assert diff["changed_components"] == ["contracts"] and diff["verdict"] == "unknown"
    confirmed = semantic_checksum_diff(before, after)
    assert confirmed["verdict"] == "refuted"
    assert confirmed["semantic_evidence"]["counterexample"]["confirmed"]
    second["payload"]["contracts"] = []
    assert diff_semantic_checksums(first, second)["verdict"] == "refuted"


def test_cross_language_checksum_reports_unknown_effect_coverage(tmp_path):
    source = tmp_path / "abs.f90"
    source.write_text("function f(n)\n  if (n >= 0) then\n    f = n\n  else\n    f = -n\n  end if\nend function\n")
    result = semantic_checksum(source, domain_assumptions={"integer": "fixed-width"})
    assert result["semantic_checksum"] and result["verdict"] == "unknown"
    assert result["payload"]["effects"] is None


def make_capsule(path):
    return create_research_capsule(path,
        finding={"id": "command-injection", "severity": "HIGH"},
        minimized_source="import os\ndef f():\n    return os.system(input())\n",
        fixed_source="def f(x):\n    return x\n",
        exploit_preconditions={"input": "attacker-controlled", "network": False},
        sandbox_argv=["python", "poc.py"],
        minimization_evidence={"confirmed": True, "method": "manual-regression-minimization"},
        proof_or_witness={"counterexample": {"confirmed": True, "inputs": {"x": "payload"}}})


def test_research_capsule_is_content_addressed_and_recheckable(tmp_path):
    path = tmp_path / "capsule.zip"
    created = make_capsule(path)
    assert created["status"] == "created" and created["verdict"] == "proved"
    other = tmp_path / "other" / "renamed.zip"
    duplicate = make_capsule(other)
    assert duplicate["artifact_sha256"] == created["artifact_sha256"]
    assert duplicate["capsule_identity"] == created["capsule_identity"]
    checked = verify_research_capsule(path)
    assert checked["capsule_identity"] == created["capsule_identity"]
    assert checked["artifacts_verified"] == 9
    assert checked["verdict"] == "unknown"  # Verification does not execute the recipe.
    with zipfile.ZipFile(path) as archive:
        manifest = json.loads(archive.read("manifest.json"))
        recipe = json.loads(archive.read("sandbox-recipe.json"))
        assert manifest["source_minimized"] and manifest["proof_status"] == "confirmed-witness"
        assert recipe["network"] == "disabled" and recipe["credentials"] == "none"
        assert archive.read("regression_test.py")


def test_research_capsule_tampering_and_unconfirmed_evidence_fail_closed(tmp_path):
    path = tmp_path / "capsule.zip"; make_capsule(path)
    with zipfile.ZipFile(path) as source:
        rows = [(name, source.read(name)) for name in source.namelist()]
    with zipfile.ZipFile(path, "w") as target:
        for name, data in rows:
            target.writestr(name, b"tampered" if name == "fixed.py" else data)
    assert verify_research_capsule(path)["verdict"] == "refuted"
    unconfirmed = create_research_capsule(tmp_path / "unknown.zip",
        finding={"id": "command-injection"},
        minimized_source="import os\nos.system(input())\n", fixed_source="def f(x):\n    return x\n",
        exploit_preconditions={}, sandbox_argv=["python", "poc.py"])
    assert unconfirmed["status"] == "created" and unconfirmed["verdict"] == "unknown"


def test_change_impact_simulation_stages_all_dependents_without_applying(tmp_path):
    root = tmp_path / "repo"; root.mkdir()
    original = "def f(x):\n    return g(x)\ndef g(x):\n    return x\n"
    (root / "app.py").write_text(original)
    (root / "downstream.py").write_text("def h(x):\n    return f(x)\n")
    spec = {"openapi": "3.0.0", "paths": {"/f": {"post": {"operationId": "f",
        "parameters": [{"name": "x", "schema": {"type": "integer"}}], "responses": {}}}}}
    changed_spec = {"openapi": "3.0.0", "paths": {}}
    result = simulate_change_impact(root,
        {"app.py": "def f(x):\n    return g(x) + 1\ndef g(x):\n    return x\n"},
        boundaries={"app.py": ["downstream"]}, api_specs={"service": {"before": spec, "after": changed_spec}})
    assert result["staged"] and not result["applied"]
    assert (root / "app.py").read_text() == original
    assert result["contracts"] and result["generated_clients"][0]["may_invalidate"]
    assert "downstream.py" in result["downstream_modules"]
    assert result["policies"]["schema"] == "pegrex.architecture-drift.v1"
    assert result["verdict"] == "unknown"


def test_impact_rejects_path_escape_and_never_touches_target(tmp_path):
    root = tmp_path / "repo"; root.mkdir(); (root / "a.py").write_text("def f():\n    return 1\n")
    result = simulate_change_impact(root, {"../escape.py": "x = 1\n"})
    assert result["verdict"] == "unknown" and not result["applied"]
    assert not (tmp_path / "escape.py").exists()


def policy():
    return [{"effect": "allow", "tool": "read"},
            {"effect": "allow", "tool": "write", "path": "src/*"},
            {"effect": "allow", "tool": "shell", "executable": "pytest"}]


def test_action_broker_separates_exact_plan_authorization_sandbox_and_evidence(tmp_path):
    plan = create_action_plan([{"tool": "write", "path": "src/result.txt", "content": "ok"},
                               {"tool": "read", "path": "src/result.txt"},
                               {"tool": "shell", "argv": ["pytest", "-q"]}])
    assert plan["status"] == "planned" and not plan["authorized"] and not plan["executed"]
    authorization = authorize_action_plan(plan, policy(), workspace=tmp_path)
    assert authorization["status"] == "authorized"
    calls = []
    def sandbox(argv, **kwargs):
        calls.append(argv)
        return {"executed": True, "confirmed": True, "returncode": 0,
                "sandbox": {"no_network": True, "ephemeral": True}}
    evidence = execute_action_plan(plan, authorization, workspace=tmp_path, sandbox_runner=sandbox)
    assert calls == [["pytest", "-q"]] and evidence["status"] == "executed"
    assert evidence["actions"][0]["filesystem_action"] == "write"
    assert evidence["actions"][2]["argv"] == ["pytest", "-q"]
    assert evidence["verdict"] == "unknown"  # Shell filesystem mutations are not enumerated.
    assert not (tmp_path / "src" / "result.txt").exists()
    checked = verify_action_evidence(evidence)
    assert checked["verified"] and checked["verdict"] == "unknown" and not checked["authenticated"]


def test_action_broker_tampered_or_unauthorized_plan_cannot_execute(tmp_path):
    plan = create_action_plan([{"tool": "shell", "argv": ["pytest", "-q"]}])
    authorization = authorize_action_plan(plan, policy(), workspace=tmp_path)
    plan["actions"][0]["argv"] = ["pytest", "--help"]
    calls = []
    result = execute_action_plan(plan, authorization, workspace=tmp_path,
        sandbox_runner=lambda *args, **kwargs: calls.append(args))
    assert result["status"] == "unknown" and not result["executed"] and not calls
    raw = create_action_plan([{"tool": "shell", "args": "pytest -q"}])
    refused = authorize_action_plan(raw, policy(), workspace=tmp_path)
    assert refused["status"] == "refused" and not refused["allowed"]
    fresh = create_action_plan([{"tool": "shell", "argv": ["pytest", "-q"]}])
    issued = authorize_action_plan(fresh, policy(), workspace=tmp_path)
    revoke_action_authorization(issued)
    revoked = execute_action_plan(fresh, issued, workspace=tmp_path,
        sandbox_runner=lambda *args, **kwargs: calls.append(args))
    assert revoked["status"] == "unknown" and not calls


def test_action_evidence_tampering_is_detected(tmp_path):
    plan = create_action_plan([{"tool": "write", "path": "src/a.txt", "content": "a"}])
    authorization = authorize_action_plan(plan, policy(), workspace=tmp_path)
    evidence = execute_action_plan(plan, authorization, workspace=tmp_path)
    evidence["hash_chain"][0]["record"]["path"] = "src/other.txt"
    assert verify_action_evidence(evidence)["verdict"] == "refuted"
