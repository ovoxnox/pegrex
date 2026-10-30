"""Regressions for lifecycle profiles and hardened public API boundaries."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from pegrex.core import OperationStatus, PathContract, get_engine
from pegrex.integrations.common import prepare_staging, read_bytes, write_json
from pegrex.states import (StatePolicyError, apply_profile_limits, authorize_operation,
                           get_profile, list_profiles)
from pegrex.toolsapi import _envelope, invoke


def test_alpha_demo_beta_profiles_are_explicit_and_non_promoting():
    manifest = list_profiles()
    assert [row["name"] for row in manifest["profiles"]] == ["alpha", "demo", "beta"]
    assert all(row["promotion_allowed"] is False for row in manifest["profiles"])
    assert get_profile("demo").allow_external_execution is False
    assert get_profile("beta").allow_release_evidence is True


def test_demo_profile_blocks_execution_and_workspace_mutation():
    with pytest.raises(StatePolicyError, match="external code execution"):
        authorize_operation("demo", "ironkernel.run")
    with pytest.raises(StatePolicyError, match="workspace-mutating"):
        authorize_operation("demo", "neural.generate", mutates_workspace=True)
    assert authorize_operation("demo", "core.audit").name == "demo"


def test_alpha_blocks_release_artifact_creation_but_beta_allows_evidence():
    with pytest.raises(StatePolicyError, match="cannot create release evidence"):
        authorize_operation("alpha", "release.create")
    assert authorize_operation("beta", "release.create").allow_release_evidence


def test_profile_budgets_reject_bool_and_over_limit_numbers():
    with pytest.raises(StatePolicyError, match="timeout_ms"):
        authorize_operation("alpha", "neural.generate", arguments={"timeout_ms": 20_000})
    with pytest.raises(StatePolicyError, match="memory_mb"):
        authorize_operation("beta", "neural.generate", arguments={"memory_mb": True})


def test_tools_api_envelope_preserves_explicit_backend_error():
    envelope = _envelope("test.error", {"status": "error", "verdict": "unknown",
                                         "unknowns": [], "data": None},
                         {"workspace": ".", "paths": []})
    assert envelope["status"] == "error"
    assert envelope["verdict"] == "unknown"


def test_tools_api_enforces_numeric_bounds_and_argv_item_types(tmp_path):
    expression = {"op": "add", "args": [{"op": "arg", "name": "x"},
                                            {"op": "const", "value": 1}]}
    negative_tolerance = invoke("ironkernel.differential", {
        "expression": expression, "inputs": {"x": [1]}, "atol": -0.25,
    }, workspace=tmp_path)
    assert negative_tolerance["status"] == "error"
    bad_argv = invoke("neural.generate", {
        "spec_path": "input.sexp", "staging": "stage", "backend_argv": ["python", 7],
    }, workspace=tmp_path)
    assert bad_argv["status"] == "error"


def test_tools_api_state_is_enforced_before_handler_execution(tmp_path):
    result = invoke("neural.generate", {
        "spec_path": "input.sexp", "staging": "stage", "backend_argv": ["python", "backend.py"],
    }, workspace=tmp_path, state="demo")
    assert result["status"] == "error"
    assert "state 'demo'" in result["error"]["message"]
    assert not (tmp_path / "stage").exists()


def test_core_engine_does_not_hide_integration_backend_error(monkeypatch):
    monkeypatch.setattr("pegrex.integrations.neural_codegen.generate_candidate", lambda **_: {
        "status": "error", "verdict": "unknown", "unknowns": [], "backend": "neural-codegen"})
    result = get_engine().execute("neural.generate", {
        "spec_path": "spec.sexp", "staging": "stage", "backend_argv": ["backend"],
    })
    assert result.status is OperationStatus.ERROR
    assert result.verdict.value == "unknown"
    assert result.unknowns


def test_path_contract_normalizes_mapping_metadata_and_rejects_scalar_constraints():
    row = PathContract.create([" x   >= 0 ", "x >= 0"], "x", metadata={"effect": "io"})
    assert row.constraints == ("x >= 0",)
    assert row.metadata == (("effect", "io"),)
    assert row.to_dict()["metadata"] == {"effect": "io"}
    with pytest.raises(TypeError, match="iterable of constraint strings"):
        PathContract.create("x >= 0", "x")


def test_staging_rejects_existing_symlinks_before_writes(tmp_path):
    root = tmp_path / "stage"
    root.mkdir()
    target = tmp_path / "outside.txt"
    target.write_text("protected", encoding="utf-8")
    (root / "candidate.py").symlink_to(target)
    with pytest.raises(ValueError, match="symbolic link"):
        prepare_staging(root)
    assert target.read_text(encoding="utf-8") == "protected"


def test_bounded_reader_rejects_symlinks(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("secret", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="non-symlink"):
        read_bytes(link)


def test_atomic_json_writer_refuses_symlink_target(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    link = tmp_path / "out.json"
    link.symlink_to(target)
    with pytest.raises(ValueError, match="symlink"):
        write_json(link, {"safe": True})
    assert json.loads(target.read_text(encoding="utf-8")) == {}


def test_cli_state_profiles_are_discoverable(capsys):
    from pegrex.cli import main
    assert main(["state", "show", "demo"]) == 0
    row = json.loads(capsys.readouterr().out)
    assert row["name"] == "demo"
    assert row["allow_external_execution"] is False


def test_state_profiles_cap_omitted_backend_defaults_without_mutating_arguments():
    original = {"spec_path": "input.sexp", "staging": "stage", "backend_argv": ["backend"]}
    effective, profile = apply_profile_limits("alpha", "neural.generate", original)
    assert effective["timeout_ms"] == profile.max_timeout_ms == 15_000
    assert effective["memory_mb"] == profile.max_memory_mb == 512
    assert "timeout_ms" not in original and "memory_mb" not in original


def test_tools_api_rejects_non_finite_numeric_values(tmp_path):
    result = invoke("ironkernel.differential", {
        "expression": {"op": "arg", "name": "x"},
        "inputs": {"x": [1.0]}, "atol": float("nan"),
    }, workspace=tmp_path)
    assert result["status"] == "error"


def test_tools_api_json_schema_union_types_keep_numeric_bounds():
    from pegrex.toolsapi import _validate_schema_value
    with pytest.raises(ValueError, match="minimum"):
        _validate_schema_value("maybe_count", 3, {"type": ["integer", "null"], "minimum": 5})
    _validate_schema_value("maybe_count", None, {"type": ["integer", "null"], "minimum": 5})


def test_state_modules_expose_production_authorization_and_effective_arguments():
    from pegrex.states import alpha, beta, demo
    original = {"spec_path": "input.sexp", "staging": "stage",
                "backend_argv": ["backend"]}
    effective = alpha.effective_arguments("neural.generate", original)
    assert effective["timeout_ms"] == 15_000
    assert effective["memory_mb"] == 512
    assert original == {"spec_path": "input.sexp", "staging": "stage",
                        "backend_argv": ["backend"]}
    assert beta.authorize("release.create").allow_release_evidence
    with pytest.raises(StatePolicyError, match="external code execution"):
        demo.effective_arguments("ironkernel.run", {"expression": {}, "inputs": {}})
    for module in (alpha, demo, beta):
        document = module.policy()
        document["promotion_allowed"] = True
        assert module.PROFILE.promotion_allowed is False
        assert module.policy()["promotion_allowed"] is False


def test_state_profile_rejects_malformed_or_promoting_definitions():
    from dataclasses import replace
    from pegrex.states import StateProfile
    with pytest.raises(ValueError, match="never authorize"):
        replace(get_profile("alpha"), promotion_allowed=True)
    with pytest.raises(ValueError, match="max_timeout_ms"):
        replace(get_profile("demo"), max_timeout_ms=True)
    with pytest.raises(StatePolicyError, match="JSON object"):
        authorize_operation("alpha", "core.audit", arguments=[])
    with pytest.raises(StatePolicyError, match="non-empty string"):
        apply_profile_limits("alpha", [], {})


def test_state_error_metadata_distinguishes_selection_from_enforcement(tmp_path):
    core_error = get_engine().execute("parse", {"source": "x"}, state="demo")
    assert core_error.metadata["state"] == "demo"
    assert core_error.metadata["state_policy_enforced"] is False
    tool_error = invoke("neural.generate", {
        "spec_path": "input.sexp", "staging": "stage", "backend_argv": ["backend"],
    }, workspace=tmp_path, state="demo")
    assert tool_error["metadata"]["state"] == "demo"
    assert tool_error["metadata"]["state_policy_enforced"] is False
    capabilities = get_engine().execute("capabilities", state="demo")
    assert capabilities.metadata["state_policy_enforced"] is True


def test_core_and_tools_manifests_share_exact_operation_schemas():
    operations = get_engine().operations()
    tools = {row["name"]: row for row in __import__("pegrex.toolsapi", fromlist=["list_tools"]).list_tools()["tools"]}
    for operation, schema in operations["schemas"].items():
        tool_name = operation if "." in operation else f"core.{operation}"
        assert tools[tool_name]["parameters"] == schema
    schema = operations["schemas"]["parse"]
    schema["properties"]["source"]["type"] = "array"
    assert get_engine().operations()["schemas"]["parse"]["properties"]["source"]["type"] == "string"


def test_reviewed_core_and_state_schemas_cover_actual_result_forms():
    from pegrex.schema import validate_document
    assert validate_document(get_engine().operations()) == []
    assert validate_document(list_profiles()) == []
    for name in ("alpha", "demo", "beta"):
        assert validate_document(get_profile(name).to_dict()) == []
    malformed = get_profile("demo").to_dict()
    malformed["promotion_allowed"] = True
    assert validate_document(malformed)
