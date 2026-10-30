import json
from pathlib import Path

from pegrex.cfg_web import render_explorer
from pegrex.framework_models import FRAMEWORK_SINKS
from pegrex.plugin_sdk import _container_command, run_plugin_containerized
from pegrex.schema import schema_catalog, validate_document
from pegrex.security_audit import analyze_security_source, correlate_iac_assumptions

ROOT = Path(__file__).resolve().parents[1]


def test_labeled_security_corpus_detects_vulnerable_and_rejects_fixed_variants():
    cases = json.loads((ROOT / "tests/data/security_effectiveness_v119.json").read_text())
    assert len(cases) >= 12
    for case in cases:
        report = analyze_security_source(case["source"], path=case["id"] + ".py")
        detected = any(row.get("id") == case["rule_id"] for row in report["findings"])
        assert detected is case["vulnerable"], (case["id"], report["findings"], report["unknowns"])


def test_secret_flow_to_logs_urls_and_process_arguments_is_composed():
    source = (
        "import os, logging, requests, subprocess\n"
        "def publish():\n"
        "    token = os.getenv('SERVICE_TOKEN')\n"
        "    logging.info(token)\n"
        "    requests.get('https://example.invalid/' + token)\n"
        "    subprocess.run(['echo', token])\n"
    )
    report = analyze_security_source(source)
    categories = {finding.get("category") for finding in report["findings"]}
    assert {"log", "url", "process-arguments", "network"} <= categories


def test_fast_deep_profiles_and_input_budget_are_explicit():
    source = "from flask import request\nimport requests\ndef f():\n u=request.args.get('u')\n requests.get(u)\n"
    fast = analyze_security_source(source, mode="fast")
    deep = analyze_security_source(source, mode="deep")
    assert fast["resource_usage"]["max_seconds"] < deep["resource_usage"]["max_seconds"]
    limited = analyze_security_source("x = 1\n" * 100, max_source_bytes=10)
    assert limited["coverage"]["status"] == "unknown"
    assert limited["unknowns"]


def test_public_schema_catalog_covers_emitted_schema_ids_and_validates_nested_types():
    catalog = schema_catalog()
    source_ids = set()
    for source_root in (ROOT / "pegrex", ROOT / "tools"):
        for path in source_root.rglob("*.py"):
            import re
            source_ids.update(re.findall(r'"schema"\s*:\s*"(pegrex\.[^"]+)"', path.read_text(errors="ignore")))
            source_ids.update(re.findall(r'(?m)^\s*[A-Z_]*SCHEMA\s*=\s*"(pegrex\.[^"]+)"', path.read_text(errors="ignore")))
    assert source_ids <= set(catalog)
    assert "pegrex.interprocedural-taint.v1" in catalog
    assert len(catalog) >= 130
    assert sum(value.get("x-peg-rex-validation-level") == "inferred-top-level" for value in catalog.values()) >= 80
    assert sum(str(value.get("x-peg-rex-validation-level", "")).startswith("envelope-only") for value in catalog.values()) <= 15
    schema_files = list((ROOT / "pegrex/jsonschemas").glob("*.json"))
    assert len(schema_files) == len(catalog)
    bad = {"schema": "pegrex.security-analysis.v1", "findings": "not-a-list", "unknowns": [], "coverage": {}}
    assert any("findings" in error for error in validate_document(bad))


def test_offline_cfg_viewer_renders_graph_and_escapes_untrusted_labels(tmp_path):
    destination = render_explorer({
        "source": "</script><script>alert(1)</script>",
        "nodes": [{"id": "entry", "label": "Entry <script>"}, {"id": "sink", "label": "Network sink"}],
        "edges": [{"source": "entry", "target": "sink", "label": "true"}],
        "paths": [{"constraint": "url is tainted"}],
    }, tmp_path / "graph.html")
    html = destination.read_text(encoding="utf-8")
    assert "Control-flow graph" in html and "addEventListener('click'" in html
    assert "</script><script>alert(1)</script>" not in html
    assert "\\u003cscript\\u003e" in html


def test_plugin_container_command_has_no_network_or_host_write_capabilities(tmp_path):
    command = _container_command(tmp_path, "plugin_impl", image="trusted-plugin:1", container_name="pegrex-test")
    joined = " ".join(command)
    for required in ("--network none", "--cap-drop ALL", "--read-only", "no-new-privileges", "--memory 256m", "--pids-limit 64", "readonly"):
        assert required in joined
    assert "/var/run/docker.sock" not in joined
    assert run_plugin_containerized(tmp_path, "plugin_impl", "x=1", docker_binary="missing-docker-binary")["status"] == "unknown"


def test_iac_correlation_remains_unknown_aware():
    result = correlate_iac_assumptions(["requires_private_storage"], [{"kind": "s3-public-read"}])
    assert result["conflicts"] and result["unknowns"] and result["coverage"] == "explicit-assumption-subset"


def test_security_effectiveness_cli_measures_every_high_severity_rule(tmp_path):
    from tools.security_effectiveness import main
    output = tmp_path / "effectiveness.json"
    assert main(["--output", str(output)]) == 0
    report = json.loads(output.read_text())
    assert report["cases"] == 52
    assert report["high_severity_mutation_audit"]["rules_checked"] == 13
    assert report["high_severity_mutation_audit"]["measured"] == 13
    assert all(row["score"] == 1.0 for row in report["high_severity_mutation_audit"]["results"])
    assert all(row["precision"] == 1 and row["recall"] == 1 for row in report["metrics"])
    assert "metamorphic unrelated-helper variants" in " ".join(report["limitations"])


def test_iac_analysis_correlates_public_database_and_unencrypted_storage():
    from pegrex.security_audit import analyze_iac_source
    source = '''resource "aws_db_instance" "db" {
  publicly_accessible = true
  storage_encrypted = false
}
resource "aws_security_group_rule" "egress" {
  type = "egress"
  protocol = "-1"
  cidr_blocks = ["0.0.0.0/0"]
}
'''
    audit = analyze_iac_source(source)
    kinds = {row["kind"] for row in audit["findings"]}
    assert {"public-database", "unencrypted-database", "unrestricted-egress"} <= kinds
    correlated = correlate_iac_assumptions(
        ["requires_private_network", "requires_encrypted_storage", "requires_restricted_egress"],
        audit["findings"])
    assert len(correlated["conflicts"]) == 3
    assert correlated["unknowns"]


def test_interprocedural_taint_and_sink_specific_sanitization():
    interprocedural = (
        "from flask import request\nimport requests\n"
        "def send(url):\n    requests.get(url)\n"
        "def endpoint():\n    url = request.args.get('url')\n    send(url)\n"
    )
    report = analyze_security_source(interprocedural)
    assert any(row.get("category") == "ssrf" and row.get("callsite") for row in report["findings"])
    html_escape_is_not_url_validation = (
        "from flask import request\nimport requests, html\n"
        "def endpoint():\n    url = request.args.get('url')\n"
        "    url = html.escape(url)\n    requests.get(url)\n"
    )
    report = analyze_security_source(html_escape_is_not_url_validation)
    assert any(row.get("category") == "ssrf" for row in report["findings"])


def test_plugin_worker_has_a_separate_result_schema():
    result = run_plugin_containerized(ROOT, "plugin_impl", "x=1", docker_binary="definitely-not-installed")
    assert result["schema"] == "pegrex.plugin-worker.v1"
    assert validate_document(result) == []


def test_analysis_session_fast_deep_modes_are_shared_and_cache_keyed():
    from pegrex.sessions import AnalysisSession
    source = "def f(x):\n    if x > 0:\n        return x\n    return 0\n"
    fast = AnalysisSession(source, mode="fast").analyze(("contracts",))
    deep = AnalysisSession(source, mode="deep").analyze(("contracts",))
    assert fast["mode"] == "fast" and deep["mode"] == "deep"
    assert fast["resource_limits"]["timeout_ms"] < deep["resource_limits"]["timeout_ms"]
    assert fast["resource_limits"]["max_paths"] < deep["resource_limits"]["max_paths"]
    assert fast["resource_limits"]["max_ast_nodes"] < deep["resource_limits"]["max_ast_nodes"]


def test_harness_policy_suite_is_a_versioned_schema_valid_result(tmp_path):
    from pegrex.harnessmutation import run_harness_policy_suite
    report = run_harness_policy_suite(base_dir=tmp_path)
    assert report["schema"] == "pegrex.harness-policy-tests.v1"
    assert report["mutation_report_schema"] == "pegrex.analyzer-mutation.v1"
    assert validate_document(report) == []


def test_cli_audit_fast_mode_is_hard_bounded_and_reports_profile(tmp_path):
    from tools.secaudit import audit_report
    source = tmp_path / "sample.py"
    source.write_text("import os\ndef f():\n    os.system(input())\n", encoding="utf-8")
    report = audit_report(str(source), "python", mode="fast")
    assert report["mode"] == "fast"
    assert report["resource_limits"]["timeout_ms"] == 3000
    assert report["resource_limits"]["max_source_bytes"] == 1_000_000
    assert report["schema"] == "pegrex.security-scan.v1"
    oversized = tmp_path / "large.py"
    oversized.write_text("x=1\n" * 300_000, encoding="utf-8")
    refused = audit_report(str(oversized), "python", mode="fast")
    assert refused["findings"][0]["kind"] == "unknown"
    assert refused["mode"] == "fast"


def test_solver_calls_are_profiled_and_budget_refuses_before_backend_call():
    from pegrex.performance import AnalysisProfile, SolverBudgetExceeded, analysis_scope, record_solver_call
    profile = AnalysisProfile()
    with analysis_scope(profile, max_solver_calls=1) as budget:
        record_solver_call("fake-solver")
        assert budget["calls"] == 1
        try:
            record_solver_call("fake-solver")
        except SolverBudgetExceeded:
            pass
        else:
            raise AssertionError("solver call over budget was not refused")
    snapshot = profile.snapshot()
    assert snapshot["counters"]["solver_calls"] == 1
    assert snapshot["counters"]["solver_budget_refusals"] == 1


def test_analysis_session_profile_is_schema_valid():
    from pegrex.sessions import AnalysisSession
    report = AnalysisSession("def f(x):\n return x\n", mode="fast").analyze(("contracts",))
    assert report["profile"]["counters"]["analyzer_calls"] == 1
    assert report["solver_budget"]["max_calls"] == 100
    assert validate_document(report) == []
