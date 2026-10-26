import json

from pegrex.policy import analyze_iac, check_policies


def test_policy_as_code_forbid_and_require_over_selected_resources():
    document = {"teams": [{"name": "a", "public": True},
                          {"name": "b", "public": False}]}
    policies = [
        {"id": "ORG-NO-PUBLIC", "select": "teams[*]",
         "forbid": [{"path": "public", "op": "equals", "value": True}]},
        {"id": "ORG-OWNER", "select": "teams[*]",
         "require": [{"path": "owner", "op": "exists"}]},
    ]
    result = check_policies(document, policies)
    assert {row["id"] for row in result["findings"]} == {"ORG-NO-PUBLIC", "ORG-OWNER"}
    assert all("content" not in row for row in result["findings"])


def test_invalid_policy_operator_is_unknown_not_clean():
    result = check_policies({"value": 1}, [{"id": "BAD", "forbid": [
        {"path": "value", "op": "python", "value": "x"}]}])
    assert result["status"] == "unknown"
    assert not result["findings"]


def test_kubernetes_policy_and_application_assumption_mismatch():
    document = {"kind": "Pod", "spec": {"hostNetwork": True, "containers": [
        {"name": "app", "securityContext": {"privileged": True}}]}}
    result = analyze_iac(json.dumps(document), format="json",
                         assumptions={"public_access": "forbidden", "privilege": "non_root"})
    ids = {row["id"] for row in result["findings"]}
    assert "IAC-K8S-PRIVILEGED" in ids
    assert "IAC-APPLICATION-ASSUMPTION" in ids
    assert all(check["satisfied"] is False for check in result["assumption_checks"])


def test_terraform_and_dockerfile_subset_coverage_is_explicit():
    terraform = analyze_iac('acl = "public-read"\ncidr_blocks = ["0.0.0.0/0"]', format="terraform")
    assert terraform["coverage"]["status"] == "pattern-based-terraform-subset"
    assert len(terraform["findings"]) == 2
    docker = analyze_iac("FROM alpine\nUSER root\n", format="dockerfile")
    assert {row["id"] for row in docker["findings"]} == {
        "IAC-DOCKER-UNPINNED-IMAGE", "IAC-DOCKER-ROOT"}


def test_parse_failure_cannot_be_clean():
    result = analyze_iac("{", format="json")
    assert result["status"] == "unknown"
    assert result["unknowns"][0]["reason"] == "iac-parse-failed"
