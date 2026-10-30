import pytest
from pegrex.agenttools import find_counterexample, query_contracts, verify_change
from pegrex.policygate import SecurityProfile, evaluate_security_policy
from pegrex.schema import validate_document


def test_fail_closed_profile_defaults_and_selective_unknowns():
    report = {"unknowns": [{"reason": "parser-unavailable", "category": "parser"},
                           {"reason": "osv-missing", "category": "dependencies"}]}
    assert not evaluate_security_policy(report)["allowed"]
    selective = SecurityProfile(unknown_categories=("parser",), require_proved=False)
    decision = evaluate_security_policy(report, selective)
    assert not decision["allowed"]
    assert len(decision["failures"]) == 1
    assert len(decision["accepted_unknowns"]) == 1


def test_explicit_unknown_allowance_remains_visible_not_clean():
    profile = SecurityProfile(allow_unknown_reasons=("osv-*",), require_proved=False)
    decision = evaluate_security_policy({"unknowns": ["osv-missing"]}, profile)
    assert decision["allowed"]
    assert decision["unknown_count"] == 1
    assert decision["accepted_unknowns"][0]["reason"] == "osv-missing"


def test_agent_contract_query_returns_versioned_contracts(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("def f(x):\n    if x > 0:\n        return x\n    return 0\n")
    result = query_contracts(str(source), function="f")
    assert result["schema"] == "pegrex.agent-evidence.v1"
    assert result["data"]["contracts"]
    assert all(row["schema"] == "pegrex.contract.v1" for row in result["data"]["contracts"])
    assert result["provenance"]["sha256"]


def test_agent_verifier_and_counterexample_are_typed(tmp_path):
    pytest.importorskip("tree_sitter", reason="counterexample confirmation requires optional parser dependencies")
    before = tmp_path / "before.py"
    after = tmp_path / "after.py"
    before.write_text("def f(x):\n    if x >= 0:\n        return x + 1\n    return 0\n")
    after.write_text("def f(x):\n    if x >= 0:\n        return x + 2\n    return 0\n")
    result = find_counterexample(str(before), str(after))
    assert result["data"]["confirmed"] is True
    assert result["verdict"] == "refuted"
    assert validate_document(result) == []
    checked = verify_change(str(before), str(after))
    assert validate_document(checked) == []
    certificate = checked["data"]["certificate"]
    assert certificate["schema"] == "pegrex.certificate.v1"
    assert certificate["verdict"] == "refuted"
    assert certificate["before_source_sha256"] == checked["provenance"]["before"]["sha256"]
    assert certificate["after_source_sha256"] == checked["provenance"]["after"]["sha256"]
    assert validate_document(certificate) == []


def test_agent_verifier_preserves_proof_and_source_identities(tmp_path):
    before = tmp_path / "before.py"
    after = tmp_path / "after.py"
    before.write_text("def f(x):\n    if x >= 0:\n        return x + 1\n    return 0\n")
    after.write_text("def f(x):\n    if x >= 0:\n        return (x + 1)\n    return 0\n")
    checked = verify_change(str(before), str(after))
    certificate = checked["data"]["certificate"]
    assert validate_document(checked) == []
    assert checked["verdict"] == "proved"
    assert certificate["verdict"] == "proved"
    assert certificate["unknowns"] == []
    assert certificate["before_source_sha256"] == checked["provenance"]["before"]["sha256"]
    assert certificate["after_source_sha256"] == checked["provenance"]["after"]["sha256"]
    assert validate_document(certificate) == []


def test_agent_tool_failure_is_unknown_evidence(tmp_path):
    missing = query_contracts(str(tmp_path / "missing.py"))
    assert missing["verdict"] == "unknown"
    assert missing["data"]["contracts"] == []
    assert missing["unknowns"]
