from __future__ import annotations
import json
from pathlib import Path

from pegrex.schema import validate_document
from pegrex.security_audit import analyze_iac_source, analyze_security_source
from tools.audit_public_schemas import audit
import tools.audit_public_schemas as schema_audit_tool

ROOT = Path(__file__).resolve().parents[1]


def test_public_schema_catalog_is_consistent_and_has_no_envelope_only_entries():
    report = audit(ROOT)
    assert report["passed"], report["errors"]
    assert report["files"] == report["catalog_entries"] >= 139
    assert report["levels"].get("reviewed", 0) >= 40
    assert report["levels"].get("envelope-only; nested contract pending stabilization", 0) == 0


def test_schema_audit_check_detects_stale_and_fresh_snapshots(tmp_path, monkeypatch):
    snapshot = tmp_path / "schema-audit.json"
    monkeypatch.setattr(schema_audit_tool, "DEFAULT_REPORT", snapshot)
    assert schema_audit_tool.main(["--check"]) == 1
    snapshot.write_text(json.dumps(audit(ROOT), indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
    assert schema_audit_tool.main(["--check"]) == 0


def test_reviewed_security_and_iac_results_validate_against_runtime_contracts():
    security = analyze_security_source("from flask import request\nimport requests\ndef f():\n requests.get(request.args.get('url'))\n")
    iac = analyze_iac_source('resource "aws_s3_bucket" "example" { acl = "public-read" }', path="main.tf")
    assert not validate_document(security), validate_document(security)
    assert not validate_document(iac), validate_document(iac)


def test_reviewed_json_schemas_match_runtime_catalog_definitions():
    for name in ("security-analysis.v1.json", "security-scan.v1.json", "iac-audit.v1.json",
                 "security-effectiveness-benchmark.v1.json", "rule-effectiveness.v1.json",
                 "plugin-worker.v1.json", "security-scan-set.v1.json", "security-provenance.v1.json",
                 "security-provenance-set.v1.json", "taint-summary.v1.json", "language-capabilities.v1.json",
                 "analysis-session.v1.json", "repository-memory.v1.json", "security-regression-memory.v1.json",
                 "resource-bounds.v1.json", "agent-action-plan.v1.json"):
        path = ROOT / "pegrex" / "jsonschemas" / name
        schema = json.loads(path.read_text(encoding="utf-8"))
        assert "x-peg-rex-validation-level" not in schema, f"{name} should be manually reviewed"
        assert schema["type"] == "object"
        assert set(schema.get("required", [])) <= set(schema.get("properties", {}))
