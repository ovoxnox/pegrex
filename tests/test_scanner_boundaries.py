import json
import pathlib
import subprocess
import sys
from types import SimpleNamespace

from tools.secaudit import (Auditor, JsonCatalog, RegexScanner, Rule,
                            gate_exit)


def test_strict_taint_unknown_is_not_discarded(tmp_path):
    source = tmp_path / "tainted.py"
    source.write_text("def run(user):\n    return eval(user)\n")
    auditor = Auditor()
    auditor.taint_rules = [{"id": "strict-eval", "langs": ["python"],
                            "severity": "HIGH", "message": "strict eval",
                            "sources": ["request\\."], "sinks": ["eval\\s*\\("],
                            "sanitizers": [], "strict_missing": True}]
    findings = auditor.audit(str(source))
    assert any(f.id == "strict-eval" and f.kind == "unknown"
               and "eval(user)" in f.evidence for f in findings), findings


def test_oversized_input_is_explicit_unknown(tmp_path):
    source = tmp_path / "large.py"
    source.write_text("#" + "a" * 2_000_001)
    findings = Auditor().audit(str(source))
    assert len(findings) == 1
    assert findings[0].id == "PEGREX-INPUT-UNKNOWN"
    assert findings[0].kind == "unknown"


def test_unsafe_rules_are_visible_coverage_gaps(tmp_path):
    catalog_path = tmp_path / "rules.json"
    catalog_path.write_text(json.dumps({"rules": [{
        "id": "unsafe-file", "langs": ["regex"], "severity": "HIGH",
        "match": {"kind": "file", "text": "(a+)+b"}}]}))
    catalog = JsonCatalog(catalog_path)
    assert list(catalog.rules("python")) == []
    assert catalog.rejected("python")[0]["id"] == "unsafe-file"


def test_regex_deadline_terminates_catastrophic_match():
    class Catalog:
        def rules(self, lang):
            return [Rule("catastrophic", ("regex",), "HIGH", "", "file", "(a+)+bcdef")]
    ast = SimpleNamespace(lang="python", src="a" * 100_000)
    findings = RegexScanner().scan(ast, Catalog(), timeout_ms=10)
    assert [f.id for f in findings] == ["PEGREX-REGEX-UNKNOWN"]
    assert findings[0].kind == "unknown"


def test_audit_exit_policy_is_explicit():
    finding = {"severity": "HIGH", "kind": "pattern"}
    unknown = {"severity": "MEDIUM", "kind": "unknown"}
    assert gate_exit([finding]) == 0
    assert gate_exit([finding], "high") == 1
    assert gate_exit([finding], "critical") == 0
    assert gate_exit([unknown], "high") == 0
    assert gate_exit([unknown], fail_on_unknown=True) == 2


def test_cli_audit_default_report_and_opt_in_failure(tmp_path):
    source = tmp_path / "unsafe.py"
    source.write_text("def f(user):\n    return eval(user)\n")
    base = [sys.executable, "-m", "pegrex.cli", "audit", str(source), "--json"]
    report = subprocess.run(base, capture_output=True, text=True)
    assert report.returncode == 0, report.stderr
    assert json.loads(report.stdout)["findings"]
    gated = subprocess.run(base + ["--fail-on", "medium"],
                           capture_output=True, text=True)
    assert gated.returncode == 1, gated.stderr
    unknown = subprocess.run(base + ["--fail-on-unknown"],
                             capture_output=True, text=True)
    assert unknown.returncode == 2, unknown.stderr


def _evidence_auditor():
    auditor = Auditor()
    auditor.taint_rules = [{
        "id": "strict-eval", "langs": ["python"], "severity": "HIGH",
        "message": "untrusted input reaches eval", "sources": ["req\\.GET"],
        "sinks": ["eval\\s*\\("], "sanitizers": [], "strict_missing": True,
        "cwe": ["CWE-94"], "owasp": ["A03:2021 Injection"],
        "references": ["https://cwe.mitre.org/data/definitions/94.html"],
    }]
    return auditor


def test_taint_sarif_has_evidence_mappings_provenance_and_justified_suppression(tmp_path):
    from pegrex.export import to_sarif
    source = tmp_path / "tainted.py"
    source.write_text(
        "def run(req):\n"
        "    value = req.GET['x']\n"
        "    return eval(value)  # pegrex:ignore strict-eval -- reviewed in SEC-42\n")
    auditor = _evidence_auditor()
    findings = [f for f in auditor.audit(str(source)) if f.id == "strict-eval"
                and f.kind == "taint"]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.suppressed is True
    assert finding.suppression["justification"] == "reviewed in SEC-42"
    assert finding.source == "req.GET"
    assert "eval(value)" in finding.sink
    assert finding.sources[0]["line"] == 2
    assert gate_exit([finding.__dict__], "high") == 0

    report = auditor.scan_report(str(source))
    assert report["provenance"]["source"]["sha256"]
    assert report["provenance"]["source"]["bytes"] == len(source.read_bytes())
    assert report["provenance"]["rule_catalog_version"].startswith("sha256:")
    assert report["provenance"]["rules"]["pattern"]["catalog_version"].startswith("sha256:")
    assert report["provenance"]["parser"]["declared_version"]
    assert report["provenance"]["parser"]["python"]
    assert (report["provenance"]["parser"]["installed_versions"]
            or report["provenance"]["parser"]["unavailable_distributions"])
    assert report["provenance"]["osv"]["mode"] == "offline"

    sarif = json.loads(to_sarif([finding.__dict__],
                                provenance=report["provenance"]))
    assert sarif["version"] == "2.1.0"
    run = sarif["runs"][0]
    rule = run["tool"]["driver"]["rules"][0]
    result = run["results"][0]
    assert rule["id"] == "strict-eval"
    assert rule["properties"]["cwe"] == ["CWE-94"]
    assert rule["properties"]["owasp"] == ["A03:2021 Injection"]
    assert rule["properties"]["security-severity"] == "8.0"
    assert result["suppressions"][0]["justification"] == "reviewed in SEC-42"
    assert result["relatedLocations"][0]["message"]["text"].startswith("Taint source")
    assert result["codeFlows"][0]["threadFlows"][0]["locations"][-1]["kinds"] == ["sink"]
    assert result["partialFingerprints"]["pegrexFindingFingerprint/v1"]
    assert run["properties"]["provenance"]["source"]["sha256"]


def test_unjustified_suppression_does_not_hide_finding(tmp_path):
    source = tmp_path / "tainted.py"
    source.write_text("def run(req):\n    return eval(req.GET['x']) "
                      "# pegrex:ignore strict-eval\n")
    finding = next(f for f in _evidence_auditor().audit(str(source))
                   if f.id == "strict-eval" and f.kind == "taint")
    assert finding.suppressed is False
    assert "requires" in finding.suppression_error
    assert gate_exit([finding.__dict__], "high") == 1


def test_cli_audit_emits_code_scanning_sarif(tmp_path):
    source = tmp_path / "unsafe.py"
    source.write_text("def f(user):\n    return eval(user)\n")
    completed = subprocess.run(
        [sys.executable, "-m", "pegrex.cli", "audit", str(source), "--sarif"],
        capture_output=True, text=True)
    assert completed.returncode == 0, completed.stderr
    document = json.loads(completed.stdout)
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"]
    assert document["runs"][0]["properties"]["provenance"]["source"]["sha256"]
