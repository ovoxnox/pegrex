import json
from pathlib import Path

from pegrex.immune import audit_repository
from pegrex.regressionnetwork import register_case, sanitize_case, minimize_case
from pegrex.observability import ingest_trace, compare_trace_revisions
from pegrex.buildgate import evaluate_release
from pegrex.hybridpriority import prioritize_paths
from pegrex.proofguidedfuzz import candidates_from_conditions, confirm_counterexample
from pegrex.composition import component_record, verify_composition


def test_immune_system_flags_boundary_and_invariant(tmp_path):
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "__init__.py").write_text("")
    (tmp_path / "pkg" / "security.py").write_text("import os\n")
    report = audit_repository(tmp_path, boundaries={"pkg.security": ["pkg.core"]},
                              invariants=[{"id": "no-os", "path": "pkg/security.py", "not_contains": "import os"}])
    assert report["status"] == "findings"
    assert {f["kind"] for f in report["findings"]} == {"architecture-boundary", "invariant-violation"}


def test_immune_parse_failure_is_unknown(tmp_path):
    (tmp_path / "bad.py").write_text("def broken(:\n")
    report = audit_repository(tmp_path)
    assert report["status"] == "unknown"
    assert report["unknowns"][0]["reason"] == "parse-error"


def test_regression_network_rejects_secret_and_registers_reproducibly(tmp_path):
    try:
        sanitize_case({"pattern": "token='supersecret123'", "test": "assert True"})
    except ValueError as e:
        assert "possible-secret" in str(e)
    else:
        raise AssertionError("secret was accepted")
    case = {"pattern": "if x < 3", "test": "assert f(2) == 2", "language": "python", "rule_id": "R1"}
    a = register_case(case, tmp_path)
    b = register_case(case, tmp_path)
    assert a["case_id"] == b["case_id"]
    assert json.loads(Path(a["path"]).read_text())["case_id"] == a["case_id"]


def test_regression_minimizer_preserves_predicate():
    case = {"pattern": "x < 3", "test": "assert f(2) == 2"}
    out = minimize_case(case, lambda c: "f(2)" in c["test"], max_attempts=30)
    assert "f(2)" in out["test"]
    assert out["minimization"]["predicate_confirmed"]


def test_observability_never_claims_proof_for_unobserved_paths():
    out = ingest_trace([{"contract_id": "c1", "path_id": "p1"}],
                       contract_index={"c1": {"paths": [{"id": "p1"}, {"id": "p2"}]}},
                       source_revision="abc")
    assert out["contracts"]["c1"]["unobserved_static_paths"] == 1
    assert out["contracts"]["c1"]["observation_is_proof"] is False
    assert "remain unresolved" in out["interpretation"]
    assert compare_trace_revisions(out, {**out, "source_revision": "def"})["status"] == "unknown"


def test_build_gate_requires_evidence_and_pinned_hash(tmp_path):
    artifact = tmp_path / "wheel.whl"
    artifact.write_bytes(b"release")
    denied = evaluate_release(artifacts={"wheel": artifact}, required_evidence=["tests", "sbom"],
                              evidence={"tests": True})
    assert denied["decision"] == "deny"
    allowed = evaluate_release(artifacts={"wheel": artifact}, required_evidence=["tests", "sbom"],
                               evidence={"tests": True, "sbom": True},
                               trusted_hashes={"wheel": __import__("hashlib").sha256(b"release").hexdigest()})
    assert allowed["decision"] == "allow"


def test_hybrid_heuristic_only_orders_paths():
    out = prioritize_paths(["a", "b", "c"], heuristic=lambda p: {"a": 0.1, "b": 0.9, "c": 0.4}[p], max_paths=2)
    assert [x["path"] for x in out["selected"]] == ["b", "c"]
    assert out["deferred"] == [0]
    assert out["heuristic_can_set_verdict"] is False


def test_proof_guided_fuzz_candidates_require_confirmation():
    generated = candidates_from_conditions(["x < 3", "y == 5", "unsupported(z)"])
    assert generated["candidates"]
    candidate = {"input": {"x": 1}, "derived_from": "x < 3"}
    assert confirm_counterexample(candidate, execute=lambda _: 2, oracle=lambda _: 1)["status"] == "confirmed"
    assert confirm_counterexample(candidate, execute=lambda _: 1, oracle=lambda _: 1)["status"] == "not-counterexample"


def test_composition_keeps_missing_obligations_unknown():
    a = component_record("a", {"post": "x>=0"}, implementation_hash="abc", obligations=["proof:a"])
    out = verify_composition([a])
    assert out["status"] == "unknown"
    out2 = verify_composition([a], checked_obligations=["proof:a"])
    assert out2["status"] == "evidence-complete"
    tampered = {**a, "contract": {"post": "true"}}
    assert verify_composition([tampered], checked_obligations=["proof:a"])["status"] == "invalid"
