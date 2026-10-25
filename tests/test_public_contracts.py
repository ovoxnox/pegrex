"""Characterization tests for the compatibility surface used by refactors."""
import json

import service
from pegrex import api
from pegrex.core import get_engine
from pegrex.core.models import (OperationResult, OperationStatus, PathContract,
                                SCHEMA_VERSION, SourceDocument, Verdict)
from pegrex.languages import LANGUAGES, capability_matrix


def test_core_serialization_schemas_are_stable():
    document = SourceDocument("π", "py", path="x.py").to_dict()
    assert document == {"schema": SCHEMA_VERSION, "path": "x.py",
                        "language": "python", "sha256": document["sha256"],
                        "characters": 1, "utf8_bytes": 2}
    row = PathContract.create(["x  >= 0"], "x", function="f").to_dict()
    assert set(row) == {"schema", "constraints", "outcome", "function",
                        "source_hash", "metadata", "identity"}
    assert row["constraints"] == ["x >= 0"] and row["outcome"] == "x"
    result = OperationResult("contracts", OperationStatus.PARTIAL, data=[row],
                             verdict=Verdict.UNKNOWN, unknowns=["fragment"])
    assert set(result.to_dict()) == {"schema", "operation", "status", "verdict",
                                     "data", "unknowns", "assumptions", "metadata"}
    assert result.to_dict()["status"] == "partial"
    assert result.to_dict()["verdict"] == "unknown"


def test_legacy_contract_and_audit_shapes_remain_available(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text("def f(x):\n    if x < 0:\n        return 0\n    return eval(x)\n")
    contracts = api.contracts(str(source))
    assert contracts and all(isinstance(cs, frozenset) and isinstance(outcome, str)
                             for cs, outcome in contracts)
    findings = api.audit(str(source))
    assert findings
    assert all(set(f) == {"id", "severity", "confidence", "line", "evidence",
                          "message", "kind", "function"} for f in findings)


def test_core_verdict_adapter_distinguishes_witness_from_unknown(tmp_path, monkeypatch):
    import pegrex.semantics as semantics
    before = tmp_path / "before.py"
    after = tmp_path / "after.py"
    before.write_text("def f():\n    return 1\n")
    after.write_text("def f():\n    return 2\n")
    monkeypatch.setattr(semantics, "verify_patch", lambda *args: {
        "verified": False, "counterexample": None, "note": "unconfirmed"})
    unknown = get_engine().verify_patch(before, after)
    assert unknown.verdict is Verdict.UNKNOWN
    assert unknown.status is OperationStatus.PARTIAL
    monkeypatch.setattr(semantics, "verify_patch", lambda *args: {
        "verified": False, "counterexample": {"inputs": {"x": 1}}})
    assert get_engine().verify_patch(before, after).verdict is Verdict.REFUTED
    monkeypatch.setattr(semantics, "verify_patch", lambda *args: {
        "verified": True, "counterexample": None})
    assert get_engine().verify_patch(before, after).verdict is Verdict.PROVED


def test_service_json_shapes_and_unknown_method():
    assert service.handle({"method": "ping"}) == {"ok": True, "pong": True}
    parsed = service.handle({"method": "parse", "params": {
        "language": "python", "source": "def f(x):\n    return x\n"}})
    assert set(parsed) == {"ok", "ast", "language", "node_count"}
    assert set(parsed["ast"]) == {"tag", "pos", "endpos", "children"}
    contracts = service.handle({"method": "contracts", "params": {
        "language": "python", "source": "def f(x):\n    return x\n"}})
    assert set(contracts) == {"ok", "status", "contract", "unknowns", "metadata"}
    assert all(isinstance(row[0], list) and len(row) == 2
               for row in contracts["contract"])
    assert service.handle({"method": "not-a-method"})["ok"] is False


def test_language_capability_wire_shape_and_registry_membership():
    matrix = capability_matrix()
    assert [row["language"] for row in matrix] == sorted(LANGUAGES)
    assert len(matrix) == 22
    assert all(set(row) == {"language", "extensions", "parser", "capabilities",
                            "contract_mode", "frontend_factory", "comment_prefix",
                            "notes", "parse_adapter", "parser_language",
                            "rule_inherits", "contract_handler", "tag_spec",
                            "function_tag", "outcome_renderer"} for row in matrix)
    assert json.loads(json.dumps(matrix)) == matrix
