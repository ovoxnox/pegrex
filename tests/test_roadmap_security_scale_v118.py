import json
from pathlib import Path

from pegrex.agent_context import MemoryGraph, compress_context
from pegrex.cfg_web import render_explorer
from pegrex.dependency_reachability import analyze_dependencies
from pegrex.framework_models import FRAMEWORK_SINKS, MODEL_VERSION
from pegrex.performance import AnalysisProfile, BoundedMemo, audit_mode, simplify_conjunction
from pegrex.plugin_sdk import conformance_test, validate_plugin
from pegrex.policy_language import evaluate_policy, load_policy
from pegrex.security_audit import analyze_iac_policy, analyze_iac_source, analyze_security_source
from pegrex.security_effectiveness import mutation_score, score_rule


def test_framework_models_include_high_risk_sink_families():
    categories = {row.category for row in FRAMEWORK_SINKS}
    assert {"ssrf", "path-traversal", "command-injection", "unsafe-deserialization", "template-injection"} <= categories
    assert MODEL_VERSION.startswith("pegrex-framework-models.")


def test_security_analysis_reports_partial_coverage_and_model_provenance():
    result = analyze_security_source("def f():\n    url = input()\n    requests.get(url)\n")
    assert result["schema"] == "pegrex.security-analysis.v1"
    assert result["security_model"] == MODEL_VERSION
    assert result["coverage"]["status"] == "partial"
    assert any(row["category"] == "ssrf" for row in result["findings"])
    assert "unknowns" in result


def test_dependency_inventory_does_not_claim_static_nonobservation_is_proof(tmp_path):
    (tmp_path / "requirements.txt").write_text("definitely-not-a-real-pegrex-package==1.0\n", encoding="utf-8")
    (tmp_path / "app.py").write_text("import importlib\n", encoding="utf-8")
    result = analyze_dependencies(tmp_path)
    assert result["schema"] == "pegrex.dependency-reachability.v1"
    assert "not_observed" in {row["state"] for row in result["dependencies"]}
    assert any("dynamic imports" in limit for limit in result["limitations"])


def test_policy_language_is_fail_closed_for_unknown_keys_and_can_require_coverage():
    policy = load_policy({"id": "org-default", "severity_at_least": "HIGH", "fail_on_unknown": True, "require_coverage": True})
    result = evaluate_policy(policy, [], unknowns=[{"reason": "solver unknown"}], coverage_complete=False)
    assert not result["passed"]
    assert result["failures"] == ["unknowns present", "coverage incomplete"]
    try:
        load_policy({"id": "bad", "run_shell": True})
    except ValueError as exc:
        assert "unsupported policy keys" in str(exc)
    else:
        raise AssertionError("unknown policy key accepted")


def test_rule_effectiveness_and_mutation_scores_use_labeled_cases():
    cases = [{"id": "vuln", "source": "danger", "vulnerable": True}, {"id": "fixed", "source": "safe", "vulnerable": False}]
    result = score_rule("R1", cases, lambda source: source == "danger")
    assert result["precision"] == 1 and result["recall"] == 1 and result["coverage"] == 1
    assert mutation_score(True, [False, True, False])["score"] == 0.6667


def test_fast_deep_modes_bounded_memo_and_formula_simplification():
    assert audit_mode("fast").max_paths < audit_mode("deep").max_paths
    memo = BoundedMemo(2)
    assert memo.get_or_compute("a", lambda: 1) == 1
    assert memo.get_or_compute("a", lambda: 2) == 1
    memo.get_or_compute("b", lambda: 2); memo.get_or_compute("c", lambda: 3)
    assert memo.stats()["size"] == 2 and memo.stats()["hits"] == 1
    assert simplify_conjunction(["True", "x > 0", "x > 0", "y < 3"]) == ["x > 0", "y < 3"]
    assert simplify_conjunction(["x", "False", "y"]) == ["False"]
    assert AnalysisProfile().snapshot()["counters"] == {}


def test_plugin_sdk_conformance_and_incompatible_version():
    plugin = {"id": "test", "api_version": "1.0", "capabilities": ["audit"], "analyze": lambda source: {"findings": []}}
    assert validate_plugin(plugin) == []
    assert conformance_test(plugin)["passed"]
    plugin["api_version"] = "0.1"
    assert not conformance_test(plugin)["passed"]


def test_evidence_context_preserves_obligations_and_memory_graph_roundtrips(tmp_path):
    context = compress_context(contracts=[{"id": "c1"}], obligations=[{"id": "unknown-proof"}], max_items=1)
    assert context["items"]["unresolved_obligations"] == [{"id": "unknown-proof"}]
    graph = MemoryGraph(tmp_path / "memory.json")
    bug = graph.add("bug", {"id": "B-1"})
    graph.add("repair", {"commit": "abc"}, relates_to=[bug])
    graph.save()
    loaded = MemoryGraph(tmp_path / "memory.json").load()
    assert len(loaded.nodes) == 2 and len(loaded.edges) == 1


def test_offline_cfg_explorer_escapes_source_and_iac_reports_partial(tmp_path):
    output = render_explorer({"source": "</script><script>alert(1)</script>", "paths": []}, tmp_path / "explorer.html")
    html = output.read_text(encoding="utf-8")
    assert "</script><script>alert(1)</script>" not in html
    assert "does not verify proofs" in html
    assert analyze_iac_source('resource "x" "y" { acl = "public-read" }')["coverage"] == "terraform-subset"
    assert analyze_iac_policy("not json")["coverage"] == "unknown"


def test_new_public_result_schemas_are_exported():
    from pegrex.schema import schema_catalog
    catalog = schema_catalog()
    assert "pegrex.dependency-reachability.v1" in catalog
    assert "pegrex.policy.v1" in catalog
    assert "pegrex.rule-effectiveness.v1" in catalog
    assert "pegrex.patch-review.v1" in catalog
    assert "pegrex.iac-audit.v1" in catalog
    assert json.loads(json.dumps(catalog))


def test_patch_review_and_repair_loop_keep_unknowns_explicit(tmp_path):
    from pegrex.agenttools import repair_candidates
    result = repair_candidates(lambda n: [{"source": "candidate"}],
        lambda source: {"status": "passed"},
        lambda source: {"verdict": "unknown"})
    assert result["status"] == "unknown"
    assert result["results"][0]["status"] == "unknown"
    assert result["unknowns"]


def test_structural_interning_adaptive_frontier_solver_portfolio_and_parallel_merge():
    from pegrex.performance import IRInterner, memory_aware_batches, merge_parallel_results, rank_path_frontier, select_solver_portfolio
    interner = IRInterner()
    first = interner.intern({"op": "add", "args": [1, 2]})
    second = interner.intern({"args": [1, 2], "op": "add"})
    assert first is second and len(interner) == 1
    ranked = rank_path_frontier([{"id": "cheap", "risk": 2, "uncertainty": 0, "proof_cost": 1}, {"id": "risky", "risk": 5, "uncertainty": 1, "proof_cost": 1}])
    assert ranked[0]["id"] == "risky"
    assert select_solver_portfolio({"shape": "finite-domain"})[0] == "finite-domain"
    batches = list(memory_aware_batches([1, 2, 3], lambda x: 700_000, max_memory_mb=1))
    assert batches == [[1], [2], [3]]
    merged = merge_parallel_results([{"findings": [{"id": "R1"}], "unknowns": ["solver timeout"]}, {"findings": [{"id": "R1"}], "unknowns": []}])
    assert len(merged["findings"]) == 1 and merged["unknowns"] == ["solver timeout"]


def test_confirmed_finding_fixture_and_high_severity_mutation_audit():
    from pegrex.security_effectiveness import evaluate_high_severity_mutations, regression_fixture_from_confirmed_finding
    fixture = regression_fixture_from_confirmed_finding({"confirmed": True, "id": "R1", "severity": "HIGH", "counterexample": {"input": "bad"}})
    assert fixture["expected"] == "detect" and fixture["review_required"]
    try:
        regression_fixture_from_confirmed_finding({"confirmed": False})
    except ValueError:
        pass
    else:
        raise AssertionError("unconfirmed finding generated a regression fixture")
    result = evaluate_high_severity_mutations([{"id": "R1", "severity": "HIGH"}, {"id": "R2", "severity": "LOW"}],
        lambda rule: {"original_detects": True, "mutants": [False, True]})
    assert result["rules_checked"] == 1 and result["measured"] == 1
