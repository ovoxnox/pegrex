from __future__ import annotations

import json
import subprocess
import sys

from tools.secaudit import Auditor, JsonCatalog, aggregate_scan_coverage


def test_file_coverage_identifies_language_executed_and_skipped_rules(tmp_path):
    source = tmp_path / "safe.py"
    source.write_text("value = 1\n")
    report = Auditor().scan_report(str(source))
    coverage = report["coverage"]
    assert coverage["schema"] == "pegrex.scan-coverage.v1"
    # The bounded JWT rule loads successfully; rule rejection remains structured UNKNOWN.
    assert coverage["status"] == "complete", coverage["unknowns"]
    assert not coverage["unknowns"]
    assert coverage["language"] == {
        "id": "python", "status": "supported", "audit": True, "taint": True}
    assert coverage["file"]["sha256"] == report["provenance"]["source"]["sha256"]
    assert coverage["rules"]["pattern"]["executed"]
    assert coverage["rules"]["taint"]["executed"]
    reasons = {row["reason"] for row in coverage["rules"]["pattern"]["skipped"]}
    assert "language-not-applicable" in reasons
    assert "no-callee-hint-in-source" in reasons


def test_unknown_language_is_not_reported_as_clean_ast_coverage(tmp_path):
    source = tmp_path / "source.unknown"
    source.write_text("eval(user)\n")
    report = Auditor().scan_report(str(source))
    coverage = report["coverage"]
    assert coverage["status"] == "partial"
    assert coverage["language"]["id"] is None
    assert any(f["id"] == "PEGREX-LANGUAGE-UNKNOWN" for f in report["findings"])
    skipped = coverage["rules"]["pattern"]["skipped"]
    assert any(row["reason"] == "language-unknown" for row in skipped)
    assert any(row["kind"] == "file" for row in coverage["rules"]["pattern"]["executed"])


def test_rejected_rule_is_structured_coverage_and_aggregate(tmp_path):
    rules = tmp_path / "rules.json"
    rules.write_text(json.dumps({"rules": [{
        "id": "unsafe-file", "langs": ["regex"], "severity": "HIGH",
        "match": {"kind": "file", "text": "(a+)+b"}}]}))
    source = tmp_path / "safe.py"
    source.write_text("value = 1\n")
    auditor = Auditor()
    auditor.catalog = JsonCatalog(rules, hot=False)
    auditor._patterns.catalog = auditor.catalog
    auditor.taint_rules = []
    report = auditor.scan_report(str(source))
    rejected = [row for row in report["coverage"]["rules"]["pattern"]["skipped"]
                if row["id"] == "unsafe-file"]
    assert rejected[0]["reason"].startswith("rule-rejected:")
    assert report["coverage"]["status"] == "partial"

    aggregate = aggregate_scan_coverage([report])
    assert aggregate["schema"] == "pegrex.scan-coverage-set.v1"
    assert aggregate["status"] == "partial"
    assert aggregate["totals"]["files"] == 1
    assert aggregate["languages"][0]["language"] == "python"
    assert aggregate["skipped_rules"][0]["file"] == str(source)


def test_directory_cli_emits_coverage_for_each_registered_language(tmp_path):
    (tmp_path / "a.py").write_text("value = 1\n")
    (tmp_path / "b.go").write_text("package main\n")
    completed = subprocess.run(
        [sys.executable, "-m", "pegrex.cli", "audit", "--dir", str(tmp_path), "--json"],
        capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    coverage = report["coverage"]
    assert coverage["totals"]["files"] == 2
    assert {row["language"] for row in coverage["languages"]} == {"python", "go"}
    assert {row["file"]["path"] for row in coverage["files"]} == {
        str(tmp_path / "a.py"), str(tmp_path / "b.go")}
