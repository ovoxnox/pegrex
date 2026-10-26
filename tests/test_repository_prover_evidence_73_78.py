from pathlib import Path

from pegrex.digitaltwin import build_repository_twin, twin_function_risk
from pegrex.drift import detect_architecture_drift
from pegrex.evidencepack import create_compliance_pack
from pegrex.incident import replay_incident
from pegrex.proverbridge import check_prover_export, export_prover
from pegrex.traceguided import prioritize_symbolic_paths


def test_compliance_pack_separates_flow_proof_and_unprovable_controls():
    source = "import os\ndef f():\n    return os.system(input())\n"
    result = create_compliance_pack(source, [
        {"id": "AC-PROCESS", "kind": "flow-contract",
         "source_categories": ["user-input"], "sink_categories": ["process-execution"],
         "frameworks": ["shell"]},
        {"id": "CC-TRAINING", "kind": "organizational"},
        {"id": "LOG-REVIEW", "kind": "source-observation", "pattern": "audit_log"},
    ])
    flow = next(row for row in result["controls"] if row["id"] == "AC-PROCESS")
    assert flow["verdict"] == "refuted" and flow["provable_from_source"]
    organizational = next(row for row in result["controls"] if row["id"] == "CC-TRAINING")
    assert organizational["verdict"] == "unknown" and not organizational["provable_from_source"]
    assert result["legal_conclusion"] is None
    assert "not legal advice" in result["disclaimer"]


def test_repository_digital_twin_joins_graphs_history_ownership_and_risk(tmp_path):
    (tmp_path / "app.py").write_text("""# owner: team-a
def f():
    return g()
def g():
    return 1
""")
    twin = build_repository_twin(tmp_path,
        change_history=[{"commit": "abc", "files": ["app.py"]}],
        risk_exposures=[{"function": "app.py::g", "kind": "internet-facing"}])
    assert twin["ownership"]["f"] == "team-a"
    assert twin["call_graph"]["files"]["f"] == "app.py"
    assert twin["contract_dependency_graph"]["nodes"]
    assert twin["change_history"][0]["commit"] == "abc"
    assert twin["risk_exposure"]["declared"][0]["function"] == "app.py::g"
    assert twin_function_risk(twin, "app.py::g")["impact"] == ["app.py::f"]
    repeated = build_repository_twin(tmp_path,
        change_history=[{"commit": "abc", "files": ["app.py"]}],
        risk_exposures=[{"function": "app.py::g", "kind": "internet-facing"}])
    assert repeated["twin_identity"] == twin["twin_identity"]


def test_architecture_drift_includes_import_and_call_coupling(tmp_path):
    package = tmp_path / "app"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "a.py").write_text("from app.b import g\ndef f():\n    return g()\n")
    (package / "b.py").write_text("def g():\n    return 1\n")
    result = detect_architecture_drift(tmp_path, {"app/a.py": ["json"], "app/b.py": ["json"]})
    kinds = {row["kind"] for row in result["drift"]}
    assert result["verdict"] == "refuted"
    assert {"unintended-import", "unintended-call-coupling"} <= kinds


def test_incident_replay_links_feasible_contracts_and_unapplied_patch_candidate(tmp_path):
    source = tmp_path / "app.py"
    original = """def f(x):
    if x >= 0:
        return x
    return -x
"""
    source.write_text(original)
    result = replay_incident([{"function": "f", "constraints": ["(x >= 0)"]}], tmp_path,
        patch_candidates=[{"id": "parenthesize", "path": "app.py",
                           "proposed_source": original.replace("return x", "return (x)")}])
    assert result["likely_paths"]
    assert any(row["match"] == "infeasible-with-trace"
               for event in result["events"] for row in event["matches"])
    assert result["patch_candidates"][0]["verdict"] == "proved"
    assert result["patch_candidates"][0]["applied"] is False
    assert result["verdict"] == "unknown"
    assert source.read_text() == original
    assert "unseen paths remain possible" in result["unknowns"][-1]


def test_trace_guidance_prioritizes_unseen_risk_without_deleting_paths():
    result = prioritize_symbolic_paths([
        {"id": "observed", "constraints": [], "risk": 1},
        {"id": "risky-unseen", "constraints": ["(x > 0)"], "risk": 5},
        {"id": "impossible", "constraints": ["(x > 0)", "(x < 0)"], "risk": 100},
    ], [{"path_id": "observed"}])
    assert result["paths"][0]["id"] == "risky-unseen"
    assert result["paths"][0]["coverage"] == "unseen"
    impossible = next(row for row in result["paths"] if row["id"] == "impossible")
    assert impossible["coverage"] == "proved-infeasible" and impossible["priority"] == 0
    assert len(result["paths"]) == 3
    assert "unseen paths are unobserved, not impossible" in result["unknowns"]
    capped = prioritize_symbolic_paths([{"id": "a"}, {"id": "b"}], max_paths=1)
    assert capped["verdict"] == "unknown" and capped["paths"] == []


def test_prover_exports_are_unchecked_until_external_evidence_arrives():
    why3 = export_prover(["(x >= 1)"], target="why3")
    smt = export_prover(["(x >= 1)"], target="smtlib")
    lean = export_prover(["(x >= 1)"], target="lean", claim="(x >= 0)")
    coq = export_prover(["(x >= 1)"], target="coq")
    assert why3["status"] == "exported" and "goal pegrex_goal" in why3["script"]
    assert "(check-sat)" in smt["script"]
    assert "sorry" in lean["script"] and "Admitted" in coq["script"]
    assert all(row["verdict"] == "unknown" and row["proof_status"] == "not-checked"
               for row in (why3, smt, lean, coq))
    checked = check_prover_export(why3, lambda target, script: {
        "verdict": "proved", "proof": {"backend": "why3-test", "certificate": "external"}})
    assert checked["verdict"] == "proved" and checked["proof_status"] == "checked"
    unsupported = check_prover_export(why3, lambda target, script: {"verdict": "proved"})
    assert unsupported["verdict"] == "unknown"
    assert export_prover(["opaque(x)"], target="lean")["status"] == "unknown"
