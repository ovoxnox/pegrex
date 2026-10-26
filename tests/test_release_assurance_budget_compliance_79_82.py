import hashlib
import json

from pegrex.assurancegraph import build_assurance_graph, invalidate_assurance, query_assurance
from pegrex.changebudget import summarize_semantic_change
from pegrex.compliancemap import build_compliance_map, query_compliance_map
from pegrex.releaseproof import create_proof_carrying_release, verify_release_pack


def write_repo(root, result="x"):
    root.mkdir()
    (root / "app.py").write_text(f"def f(x):\n    return {result}\n")
    (root / "package-lock.json").write_text(json.dumps({"packages": {
        "node_modules/demo": {"version": "1.0.0", "integrity": "sha256-" + "AA=="}}}))


def test_proof_carrying_release_rechecks_all_available_upstreams(tmp_path):
    before, after = tmp_path / "before", tmp_path / "after"
    write_repo(before); write_repo(after)
    artifact = tmp_path / "release.whl"; artifact.write_bytes(b"deterministic artifact")
    pack = create_proof_carrying_release(after, previous_root=before,
        lockfile=after / "package-lock.json", subjects=[artifact], builder_id="local-test",
        command_argv=["python", "-m", "build"], build_type="local-test")
    assert pack["schema"] == "pegrex.proof-carrying-release.v1"
    assert pack["api_contracts"]["entries"][0]["verdict"] == "proved"
    assert pack["sbom"]["bomFormat"] == "CycloneDX"
    assert pack["semantic_diff"]["verdict"] == "proved"
    assert pack["verdict"] == "unknown"  # Unsigned builder identity remains unknown.
    assert pack["unknown_summary"]["summary_sha256"]
    checked = verify_release_pack(pack, after, previous_root=before,
        lockfile=after / "package-lock.json", subject_paths=[artifact])
    assert checked["verdict"] == "unknown" and "release_identity" in checked
    artifact.write_bytes(b"tampered")
    assert verify_release_pack(pack, after, previous_root=before,
        lockfile=after / "package-lock.json", subject_paths=[artifact])["verdict"] == "refuted"


def test_release_missing_previous_and_dependency_evidence_is_machine_unknown(tmp_path):
    root = tmp_path / "repo"; root.mkdir(); (root / "a.py").write_text("def f():\n    return 1\n")
    subject = tmp_path / "a.out"; subject.write_text("x")
    pack = create_proof_carrying_release(root, subjects=[subject], builder_id="local",
        command_argv=["build"], build_type="test")
    categories = pack["unknown_summary"]["by_category"]
    assert categories["sbom"] == 1 and categories["previous-release"] == 1
    assert pack["unknown_summary"]["count"] == len(pack["unknown_summary"]["entries"])


def test_assurance_graph_exact_upstream_change_invalidates_claim_not_unchanged_content():
    digest = hashlib.sha256(b"api").hexdigest()
    claims = [{"id": "api-f", "kind": "api-contract", "verdict": "proved",
               "evidence": [{"id": "certificate-f", "verdict": "proved",
                             "upstream": [{"id": "app.py::f", "sha256": digest}]}]}]
    graph = build_assurance_graph(claims)
    assert graph["verdict"] == "proved"
    assert graph["edges"][0]["evidence_id"] == "certificate-f"
    unchanged = invalidate_assurance(graph, {"app.py::f": {"sha256": digest}})
    assert unchanged["verdict"] == "proved" and not unchanged["invalidated_edges"]
    changed = invalidate_assurance(graph, {"app.py::f": {"sha256": "0" * 64}})
    assert changed["verdict"] == "unknown" and changed["nodes"][0]["verdict"] == "unknown"
    assert changed["invalidated_edges"][0]["upstream_sha256"] == digest
    assert query_assurance(changed, verdict="unknown")["count"] == 1


def test_assurance_proof_without_upstream_and_tampering_fail_closed():
    graph = build_assurance_graph([{"id": "policy", "kind": "access-policy", "verdict": "proved",
        "evidence": [{"id": "proof", "verdict": "proved", "upstream": []}]}])
    assert graph["verdict"] == "unknown"
    graph["nodes"][0]["statement"] = "tampered"
    assert invalidate_assurance(graph, {})["verdict"] == "unknown"


def test_semantic_change_budget_covers_five_dimensions_and_limits(tmp_path):
    before, after = tmp_path / "before", tmp_path / "after"
    write_repo(before); write_repo(after)
    (after / "app.py").write_text("import os\ndef f(x):\n    if x > 0:\n        return os.system(input())\n    return x + 1\n")
    (after / "package-lock.json").write_text(json.dumps({"packages": {
        "node_modules/demo": {"version": "2.0.0"}}}))
    result = summarize_semantic_change(before, after, budget={
        "public_contract_changes": 0, "security_surface_changes": 0,
        "dependency_changes": 0, "complexity_increase": 0})
    assert result["public_contract_changes"] and result["security_surface_changes"]
    assert result["dependency_changes"] and result["complexity_changes"]
    assert result["unknown_regions"] == []
    assert result["verdict"] == "refuted" and len(result["budget_exceeded"]) == 4
    assert result["metrics"]["complexity_increase"] >= 1


def test_change_budget_parser_gaps_do_not_look_like_no_change(tmp_path):
    before, after = tmp_path / "before", tmp_path / "after"
    write_repo(before); write_repo(after)
    (after / "broken.py").write_text("def broken(:\n")
    result = summarize_semantic_change(before, after)
    assert result["verdict"] == "unknown" and result["status"] == "unknown"
    assert result["unknown_regions"]


def compliance_inputs():
    return ([{"id": "pii", "labels": ["personal"]}],
            [{"id": "flow-1", "classification": "pii", "source": {"function": "input"},
              "sink": {"function": "delete"}, "trace": ["input", "delete"],
              "evidence": {"sha256": "a" * 64}}],
            [{"classification": "pii", "retention_function": "retain", "deletion_function": "delete"}],
            [{"id": "kms", "classifications": ["pii"], "control": "encryption",
              "resource": "db", "verdict": "proved"}])


def test_executable_compliance_map_is_queryable_and_legal_review_is_human():
    graph = build_compliance_map(*compliance_inputs(), legal_review={
        "reviewer": "counsel", "decision": "reviewed retention interpretation"})
    assert graph["legal_interpretation"]["status"] == "human-reviewed"
    assert graph["legal_interpretation"]["proved_by_code"] is False
    result = query_compliance_map(graph, classification="pii")
    assert len(result["nodes"]) == 5 and result["edges"]
    assert any(row["kind"] == "deletion-function" for row in result["nodes"])
    assert result["verdict"] == "unknown"  # Operational effectiveness is not source-proved.


def test_compliance_map_missing_controls_and_query_cap_are_unknown():
    graph = build_compliance_map([{"id": "pii"}], [], [], [])
    assert graph["verdict"] == "unknown"
    assert graph["legal_interpretation"]["status"] == "human-review-required"
    assert any("infrastructure control mapping absent" in row for row in graph["unknowns"])
    capped = query_compliance_map(graph, max_results=0)
    assert capped["verdict"] == "unknown" and capped["nodes"] == []
