from pegrex.flow import analyze_secrets
from pegrex.frameworkpacks import analyze_with_frameworks, framework_packs
from pegrex.securitycontracts import check_security_contract, process_execution_contract


def test_framework_pack_findings_include_exact_rule_ast_and_flow_path():
    source = """import subprocess
value = input()
subprocess.run(value)
"""
    report = analyze_with_frameworks(source, ("shell",))
    finding = next(row for row in report["findings"] if row["id"] == "shell-process")
    assert finding["rule"]["pattern"] and finding["rule_pack"] == "shell"
    assert finding["matched_ast"]["node_type"] == "Call"
    assert "subprocess.run(value)" in finding["matched_ast"]["source"]
    assert finding["flow_path"][0]["kind"] == "source"
    assert finding["flow_path"][-1]["kind"] == "sink"
    assert finding["evidence_strength"] == "static-source-to-sink"


def test_security_contract_refutes_flow_and_accepts_declared_transformation():
    contract = process_execution_contract()
    bad = check_security_contract("""import subprocess
subprocess.run(input())
""", contract)
    assert bad["verdict"] == "refuted" and bad["violations"]
    good = check_security_contract("""import subprocess, shlex
subprocess.run(shlex.quote(input()))
""", contract)
    assert good["verdict"] == "proved" and good["holds"] is True


def test_secret_configuration_to_log_and_network_is_traceable():
    source = """import os, logging, requests
password = os.getenv("PASSWORD")
logging.info(password)
requests.post("https://example.invalid", password)
"""
    report = analyze_secrets(source)
    categories = {row["category"] for row in report["findings"]}
    assert {"log", "network"} <= categories
    finding = next(row for row in report["findings"] if row["category"] == "log")
    assert finding["sources"][0]["category"] == "configuration-secret"
    assert finding["flow_path"]


def test_unknown_framework_pack_is_not_a_clean_scan():
    report = analyze_with_frameworks("value = input()", ("not-a-framework",))
    assert report["unknowns"] and not report["findings"]
    packs = framework_packs(("shell", "shell"))
    assert len(packs["packs"]) == 1
