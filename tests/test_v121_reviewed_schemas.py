from __future__ import annotations

from pegrex.agenttools import agent_tool_manifest
from pegrex.finiteproof import check_finite_domain_proof
from pegrex.modelcheck import bounded_check
from pegrex.pathcontract_v2 import validate_path_contract_v2
from pegrex.policygate import evaluate_security_policy
from pegrex.schema import validate_document
from pegrex.testpromotion import promote_counterexample
from pegrex.toolsapi import invoke, list_tools


def _assert_valid(document):
    errors = validate_document(document)
    assert not errors, errors


def test_agent_manifest_and_tools_api_contracts_validate():
    _assert_valid(agent_tool_manifest())
    _assert_valid(list_tools())
    _assert_valid(invoke("not-a-registered-tool", workspace="."))


def test_bounded_model_check_result_schema_covers_proved_and_unknown_shapes():
    proved = bounded_check([0], lambda state, depth: [state + 1] if state < 1 else [],
                           lambda state: state < 2, max_depth=3)
    unknown = bounded_check([0], lambda state, depth: [state + 1],
                            lambda state: True, max_depth=0)
    _assert_valid(proved)
    _assert_valid(unknown)


def test_path_contract_validation_schema_covers_invalid_input():
    _assert_valid(validate_path_contract_v2({"schema": "not-a-contract"}))


def test_finite_domain_proof_schema_covers_unknown_and_verified_results():
    unknown = check_finite_domain_proof({"schema": "unsupported"})
    proved = check_finite_domain_proof({
        "schema": "pegrex.finite-domain-proof.v1", "schema_version": 1,
        "claim": "finite-domain-equivalent", "domains": {"x": [0, 1]},
        "before": {"op": "var", "name": "x"},
        "after": {"op": "var", "name": "x"},
    })
    _assert_valid(unknown)
    _assert_valid(proved)


def test_security_policy_decision_schema_covers_denial_and_unknown_evidence():
    result = evaluate_security_policy({"verdict": "unknown", "unknowns": ["parser unavailable"]})
    _assert_valid(result)


def test_test_promotion_schema_covers_created_and_idempotent_results(tmp_path):
    output = tmp_path / "test_promoted.py"
    counterexample = {"confirmed": True, "inputs": {"value": 3}}
    first = promote_counterexample(counterexample, "target", output, expected=6)
    second = promote_counterexample(counterexample, "target", output, expected=6)
    _assert_valid(first)
    _assert_valid(second)
