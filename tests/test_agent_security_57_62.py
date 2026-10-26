import json
import subprocess
import sys
from pathlib import Path

from pegrex.attackgraph import AttackPathGraph, build_attack_graph
from pegrex.exploitability import assess_exploitability
from pegrex.harnessmutation import run_harness_policy_suite
from pegrex.pocsandbox import run_poc
from pegrex.policy import analyze_iac
from pegrex.regressionmemory import register_finding_fix, verify_regression_memory


def rule_ids(report):
    return {row["id"] for row in report["findings"]}


def test_iac_formats_have_parser_specific_findings_and_confidence():
    terraform = analyze_iac('acl = "public-read"\n', format="terraform")
    assert "IAC-S3-PUBLIC-READ" in rule_ids(terraform)
    assert terraform["coverage"]["confidence"] == "medium"

    kubernetes = analyze_iac("""
apiVersion: v1
kind: Pod
spec:
  containers:
    - name: app
      securityContext:
        privileged: true
""", format="kubernetes")
    assert "IAC-K8S-PRIVILEGED" in rule_ids(kubernetes)
    assert kubernetes["coverage"]["confidence"] == "high"

    docker = analyze_iac("FROM alpine:latest\nEXPOSE 22\n", format="dockerfile")
    assert {"IAC-DOCKER-UNPINNED-IMAGE", "IAC-DOCKER-SSH", "IAC-DOCKER-ROOT"} <= rule_ids(docker)
    assert docker["coverage"]["confidence"] == "medium"

    iam = analyze_iac(json.dumps({"Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}), format="json")
    assert "IAC-IAM-WILDCARD-ADMIN" in rule_ids(iam)


def test_helm_is_static_low_confidence_and_parse_failures_are_unknown():
    report = analyze_iac("""
apiVersion: v1
kind: Pod
metadata:
  name: {{ .Values.name }}
spec:
  containers: []
""", format="helm")
    assert report["status"] == "unknown"
    assert report["coverage"]["confidence"] == "low"
    assert report["coverage"]["template_evaluation"] == "unavailable"
    assert "helm-template-evaluation-unavailable" in {row["reason"] for row in report["unknowns"]}

    malformed = analyze_iac("kind: [", format="helm")
    assert malformed["status"] == "unknown"
    assert malformed["coverage"]["status"] == "parse-failed"
    assert malformed["coverage"]["confidence"] == "low"


def test_network_policy_world_ingress_and_egress_are_visible():
    report = analyze_iac(json.dumps({
        "kind": "NetworkPolicy",
        "spec": {
            "ingress": [{"from": [{"ipBlock": {"cidr": "0.0.0.0/0"}}]}],
            "egress": [{"to": [{"ipBlock": {"cidr": "::/0"}}]}],
        },
    }), format="json")
    assert {"IAC-NETPOL-WORLD-INGRESS", "IAC-NETPOL-WORLD-EGRESS"} <= rule_ids(report)


def test_attack_graph_connects_exposure_identity_dependency_and_code_flow():
    graph = build_attack_graph(
        assets=[{"id": "web"}],
        identities=[{"id": "deployer", "can_access": ["web"]}],
        exposures=[{"from": "internet", "service": "https", "asset": "web"}],
        dependencies=[{"name": "demo", "id": "CVE-DEMO", "reachability": "reachable", "assets": ["web"]}],
        flow_reports=[{"findings": [{
            "id": "command-injection", "file": "app.py", "line": 3,
            "sources": [{"category": "request", "name": "input"}],
            "matched_ast": "Call", "evidence_strength": "static-flow", "flow_path": ["input", "system"],
        }]}],
    )
    paths = graph.paths()
    assert paths["complete"] and not paths["unknowns"]
    assert any("vulnerability:CVE-DEMO" in row["nodes"] and row["nodes"][0] == "internet" for row in paths["paths"])
    assert any("vulnerability:CVE-DEMO" in row["nodes"] and row["nodes"][0] == "deployer" for row in paths["paths"])
    assert any(row["nodes"][-1].startswith("sink:command-injection:") for row in paths["paths"])
    assert {node["kind"] for node in graph.payload()["nodes"]} >= {
        "asset", "identity", "exposure", "dependency", "source", "sink", "reachable-vulnerability"}


def test_attack_path_cap_is_unknown_and_not_a_partial_clean_answer():
    graph = AttackPathGraph()
    graph.node("sink", "sink")
    for name in ("source:a", "source:b"):
        graph.node(name, "source")
        graph.edge(name, "sink", "reaches")
    report = graph.paths(max_paths=1)
    assert report["verdict"] == "unknown"
    assert not report["complete"] and report["paths"] == []
    assert "attack-path bound reached; path set incomplete" in report["unknowns"]


def test_exploitability_ladder_requires_confirmation_and_real_isolation_evidence():
    report = assess_exploitability("F-1", [
        {"level": "pattern-match", "confirmed": True},
        {"level": "confirmed-test", "confirmed": True, "test": "pytest"},
        {"level": "symbolic-witness", "confirmed": True, "model": {"x": 1}},
        {"level": "sandboxed-reproduction", "confirmed": True, "isolation": {
            "ephemeral": True, "isolated": True, "no_credentials": True, "no_network": True}},
    ])
    assert report["level"] == "sandboxed-reproduction"
    assert report["complete_ladder"] and report["unknowns"] == []

    insufficient = assess_exploitability("F-2", [
        {"level": "sandboxed-reproduction", "confirmed": True, "isolation": {"isolated": True}},
        {"level": "confirmed-test", "confirmed": False},
    ])
    assert insufficient["level"] == "none"
    assert not insufficient["complete_ladder"]


def test_poc_refuses_raw_shell_and_unavailable_isolation(monkeypatch):
    raw = run_poc("python -c 'print(1)'")
    assert raw["status"] == "unknown" and not raw["executed"]
    monkeypatch.setattr("pegrex.pocsandbox._executables", lambda: (None, None))
    unavailable = run_poc(["python", "-c", "print(1)"])
    assert unavailable["status"] == "unknown" and not unavailable["executed"]
    assert "ephemeral isolated sandbox unavailable; PoC execution refused" in unavailable["unknowns"]


def test_harness_policy_mutation_suite_checks_safe_baseline_and_bypasses(tmp_path):
    report = run_harness_policy_suite(base_dir=tmp_path)
    assert report["safe_baseline_allowed"]
    assert report["verdict"] == "proved"
    assert report["expectation_failures"] == []
    statuses = {row["name"]: row["status"] for row in report["controls"]}
    assert statuses["raw-shell"] == "survived"
    assert statuses["policy-mutation-push"] == "killed"
    assert all(row["baseline_detected"] for row in report["controls"])


def test_fixed_finding_generates_executable_regression_and_negative_control(tmp_path):
    vulnerable = "import os\ndef f():\n    return os.system(input())\n"
    fixed = "def f(x):\n    return x\n"
    test_path = tmp_path / "test_security_regression.py"
    memory_path = tmp_path / "memory.json"
    registered = register_finding_fix(
        {"id": "command-injection"}, vulnerable, fixed, test_path, memory_path)
    assert registered["status"] == "registered"
    verified = verify_regression_memory(memory_path)
    assert verified["status"] == "ok" and verified["entries"] == 1
    executed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", str(test_path)],
        cwd=Path(__file__).parents[1], capture_output=True, text=True, shell=False, timeout=60)
    assert executed.returncode == 0, executed.stdout + executed.stderr
    assert "2 passed" in executed.stdout

    test_path.write_text(test_path.read_text() + "\n# tampered\n")
    assert verify_regression_memory(memory_path)["status"] == "unknown"


def test_regression_memory_refuses_an_unfixed_negative_control(tmp_path):
    vulnerable = "import os\nos.system(input())\n"
    result = register_finding_fix(
        {"id": "command-injection"}, vulnerable, vulnerable,
        tmp_path / "should_not_exist.py", tmp_path / "memory.json")
    assert result["status"] == "refuted"
    assert not (tmp_path / "should_not_exist.py").exists()
