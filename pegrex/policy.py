"""Declarative policy-as-code and deployment/application assumption checks.

Policies are data, never Python expressions. Missing parsers, invalid policy
operators, and unsupported input formats produce explicit UNKNOWN evidence.
"""
from __future__ import annotations

import json
import re
from typing import Any

from .schema import finding_document, unknown_document

IAC_SCHEMA = "pegrex.iac-analysis.v1"
POLICY_SCHEMA = "pegrex.policy-checks.v1"


def _select(document: Any, path: str) -> list[tuple[str, Any]]:
    if path in {"", "$"}:
        return [("$", document)]
    current = [("$", document)]
    for part in path.removeprefix("$.").split("."):
        following = []
        wildcard = part.endswith("[*]")
        key = part[:-3] if wildcard else part
        for location, value in current:
            if key and isinstance(value, dict) and key in value:
                value = value[key]
                location = f"{location}.{key}"
            elif key:
                continue
            if wildcard:
                if isinstance(value, list):
                    following.extend((f"{location}[{index}]", item)
                                     for index, item in enumerate(value))
            else:
                following.append((location, value))
        current = following
    return current


def _assertion(item: Any, assertion: dict) -> tuple[bool, str | None]:
    op = assertion.get("op", "exists")
    values = [value for _, value in _select(item, assertion.get("path", "$"))]
    expected = assertion.get("value")
    if op == "exists":
        result = bool(values)
        if expected is not None:
            result = result is bool(expected)
    elif op == "equals":
        result = bool(values) and all(value == expected for value in values)
    elif op == "not_equals":
        result = bool(values) and all(value != expected for value in values)
    elif op == "contains":
        result = bool(values) and all(expected in value for value in values
                                     if isinstance(value, (list, dict, str)))
    elif op == "matches":
        try:
            result = bool(values) and all(re.fullmatch(str(expected), str(value))
                                         for value in values)
        except re.error as error:
            return False, f"invalid policy regex: {error}"
    elif op in {"gte", "lte", "gt", "lt"}:
        operations = {"gte": lambda a, b: a >= b, "lte": lambda a, b: a <= b,
                      "gt": lambda a, b: a > b, "lt": lambda a, b: a < b}
        try:
            result = bool(values) and all(operations[op](value, expected) for value in values)
        except TypeError:
            result = False
    elif op == "in":
        result = bool(values) and all(value in expected for value in values)
    else:
        return False, f"unsupported policy operator: {op}"
    return result, None


def check_policies(document: Any, policies: list[dict]) -> dict:
    """Implement check policies with the module's explicit API and failure semantics."""
    findings, unknowns = [], []
    for policy in policies:
        policy_id = policy.get("id")
        if not policy_id:
            unknowns.append(unknown_document("policy-without-id", details={"policy": policy}).copy())
            continue
        selected = _select(document, policy.get("select", "$"))
        if not selected:
            unknowns.append(unknown_document("policy-select-empty",
                                             source=policy_id, details={"select": policy.get("select", "$")}))
            continue
        for location, item in selected:
            forbid = [_assertion(item, row) for row in policy.get("forbid", [])]
            require = [_assertion(item, row) for row in policy.get("require", [])]
            for _, error in forbid + require:
                if error:
                    unknowns.append(unknown_document("invalid-policy", source=policy_id,
                                                     details={"reason": error}))
            violated = bool(forbid) and all(result and not error for result, error in forbid)
            missing = any(not result and not error for result, error in require)
            if violated or missing:
                findings.append(finding_document({
                    "id": policy_id, "severity": policy.get("severity", "MEDIUM"),
                    "confidence": "high", "line": 1, "evidence": location,
                    "message": policy.get("message", "organization policy violated"),
                    "kind": "policy", "path": location,
                    "reason": "forbidden-state" if violated else "missing-requirement",
                    "suppressed": False}))
    return {"schema": POLICY_SCHEMA, "status": "unknown" if unknowns else "ok",
            "findings": findings, "unknowns": unknowns,
            "coverage": {"policies": len(policies), "evaluated": len(policies) - len(unknowns)}}


def _finding(rule_id, message, path, severity="HIGH", kind="iac"):
    return finding_document({"id": rule_id, "severity": severity, "confidence": "high",
        "line": 1, "evidence": path, "message": message, "kind": kind,
        "path": path, "suppressed": False})


def _iam(document, findings):
    statements = document.get("Statement", []) if isinstance(document, dict) else []
    if isinstance(statements, dict):
        statements = [statements]
    for index, statement in enumerate(statements):
        if statement.get("Effect") != "Allow":
            continue
        actions = statement.get("Action", [])
        resources = statement.get("Resource", [])
        actions = actions if isinstance(actions, list) else [actions]
        resources = resources if isinstance(resources, list) else [resources]
        path = f"$.Statement[{index}]"
        if "*" in actions and "*" in resources:
            findings.append(_finding("IAC-IAM-WILDCARD-ADMIN", "policy grants all actions on all resources", path))
        elif "*" in actions:
            findings.append(_finding("IAC-IAM-WILDCARD-ACTION", "policy grants every action", path))
        if "s3:*" in actions:
            findings.append(_finding("IAC-S3-FULL-CONTROL", "policy grants full S3 control", path))


def _kubernetes(document, findings):
    if not isinstance(document, dict) or "kind" not in document:
        return
    path = f"$.{document.get('kind', 'resource')}"
    spec = document.get("spec", {})
    if document.get("kind") == "NetworkPolicy":
        for direction in ("ingress", "egress"):
            for index, rule in enumerate(spec.get(direction, []) or []):
                peers = rule.get("from" if direction == "ingress" else "to", []) or []
                for peer in peers:
                    cidr = peer.get("ipBlock", {}).get("cidr") if isinstance(peer, dict) else None
                    if cidr in {"0.0.0.0/0", "::/0"}:
                        findings.append(_finding("IAC-NETPOL-WORLD-" + direction.upper(),
                            f"NetworkPolicy {direction} permits every source/destination",
                            f"{path}.spec.{direction}[{index}]"))
    pod_spec = spec.get("template", {}).get("spec", spec)
    if pod_spec.get("hostNetwork") is True:
        findings.append(_finding("IAC-K8S-HOST-NETWORK", "pod shares the host network", path))
    containers = list(pod_spec.get("containers", []) or []) + list(pod_spec.get("initContainers", []) or [])
    for index, container in enumerate(containers):
        location = f"{path}.containers[{index}]"
        security = container.get("securityContext", {})
        if security.get("privileged") is True:
            findings.append(_finding("IAC-K8S-PRIVILEGED", "container is privileged", location))
        if security.get("allowPrivilegeEscalation") is not False:
            findings.append(_finding("IAC-K8S-PRIVILEGE-ESCALATION", "privilege escalation is not disabled", location, "MEDIUM"))
        if "limits" not in container.get("resources", {}):
            findings.append(_finding("IAC-K8S-NO-RESOURCE-LIMITS", "container has no resource limits", location, "MEDIUM"))


def _terraform(source, findings):
    checks = (("IAC-S3-PUBLIC-READ", r'acl\s*=\s*"public-read"', "bucket ACL permits public reads"),
              ("IAC-INGRESS-WORLD", r'cidr_blocks\s*=\s*\[[^\]]*"0\.0\.0\.0/0"', "ingress is open to the world"),
              ("IAC-TF-WILDCARD-ACTION", r'Action\s*=\s*"\\?\*"', "Terraform policy contains a wildcard action"))
    for rule_id, pattern, message in checks:
        if re.search(pattern, source, re.IGNORECASE | re.DOTALL):
            findings.append(_finding(rule_id, message, "terraform"))


def _dockerfile(source, findings):
    users = []
    for line in source.splitlines():
        text = line.strip()
        if not text or text.startswith("#"):
            continue
        instruction, _, argument = text.partition(" ")
        instruction = instruction.upper()
        if instruction == "FROM" and argument and (":" not in argument or argument.endswith(":latest")):
            findings.append(_finding("IAC-DOCKER-UNPINNED-IMAGE", "base image is not pinned to a non-latest tag", "Dockerfile", "MEDIUM"))
        elif instruction == "USER":
            users.append(argument)
        elif instruction == "EXPOSE" and argument == "22":
            findings.append(_finding("IAC-DOCKER-SSH", "container exposes SSH", "Dockerfile", "MEDIUM"))
    if not users or users[-1] in {"root", "0"}:
        findings.append(_finding("IAC-DOCKER-ROOT", "container may run as root", "Dockerfile", "MEDIUM"))


def _parser_coverage(format, status, path):
    parser = {"terraform": "bounded-regex-hcl-subset", "tf": "bounded-regex-hcl-subset",
              "dockerfile": "line-oriented-instruction-parser",
              "helm": "PyYAML safe_load_all after template masking",
              "json": "stdlib json"}.get(format, "PyYAML safe_load_all")
    confidence = ("medium" if format in {"terraform", "tf", "dockerfile"}
                  else "low" if format == "helm" else "high")
    return {"status": status, "path": path, "parser": parser,
            "confidence": confidence,
            "template_evaluation": "unavailable" if format == "helm" else "not-applicable"}


def analyze_iac(source: str, *, format: str, path="<memory>", assumptions=None,
                policies=()) -> dict:
    """Implement analyze iac with the module's explicit API and failure semantics."""
    format = format.lower()
    findings, unknowns = [], []
    document = None
    coverage = "parsed-subset"
    try:
        if format == "json":
            document = json.loads(source)
            _iam(document, findings)
            _kubernetes(document, findings)
        elif format == "helm":
            try:
                import yaml
            except ImportError:
                return {"schema": IAC_SCHEMA, "status": "unknown", "findings": [],
                        "unknowns": [unknown_document("yaml-parser-unavailable", source=path)],
                        "assumption_checks": [], "coverage": _parser_coverage(format, "refused", path)}
            templated = bool(re.search(r"{{.*?}}", source, re.DOTALL))
            rendered = re.sub(r"{{.*?}}", "HELM_VALUE", source, flags=re.DOTALL)
            documents = list(yaml.safe_load_all(rendered))
            for document in documents:
                _iam(document, findings)
                _kubernetes(document, findings)
            document = documents
            coverage = "helm-static-yaml-subset"
            if templated:
                unknowns.append(unknown_document("helm-template-evaluation-unavailable", source=path,
                    details={"method": "template expressions replaced for structural parsing only"}))
        elif format in {"yaml", "yml", "kubernetes", "k8s"}:
            try:
                import yaml
            except ImportError:
                return {"schema": IAC_SCHEMA, "status": "unknown", "findings": [],
                        "unknowns": [unknown_document("yaml-parser-unavailable", source=path)],
                        "assumption_checks": [], "coverage": {"status": "refused"}}
            documents = list(yaml.safe_load_all(source))
            for document in documents:
                _iam(document, findings)
                _kubernetes(document, findings)
            document = documents
        elif format in {"terraform", "tf"}:
            _terraform(source, findings)
            coverage = "pattern-based-terraform-subset"
        elif format == "dockerfile":
            _dockerfile(source, findings)
            coverage = "dockerfile-instruction-subset"
        else:
            return {"schema": IAC_SCHEMA, "status": "unknown", "findings": [],
                    "unknowns": [unknown_document("unsupported-iac-format", source=path,
                                                  details={"format": format})],
                    "assumption_checks": [], "coverage": {"status": "refused"}}
    except (ValueError, TypeError, AttributeError) as error:
        return {"schema": IAC_SCHEMA, "status": "unknown", "findings": [],
                "unknowns": [unknown_document("iac-parse-failed", source=path,
                                              details={"reason": str(error)})],
                "assumption_checks": [], "coverage": _parser_coverage(format, "parse-failed", path)}
    except Exception as error:
        if format in {"yaml", "yml", "kubernetes", "k8s", "helm"}:
            return {"schema": IAC_SCHEMA, "status": "unknown", "findings": [],
                    "unknowns": [unknown_document("iac-parse-failed", source=path,
                                                  details={"reason": str(error)})],
                    "assumption_checks": [], "coverage": _parser_coverage(format, "parse-failed", path)}
        raise
    assumption_checks = []
    for name, expected in (assumptions or {}).items():
        if name == "public_access" and expected == "forbidden":
            related = [row for row in findings if any(word in row["id"] for word in ("PUBLIC", "WORLD", "HOST-NETWORK"))]
            assumption_checks.append({"assumption": name, "expected": expected,
                                      "satisfied": not related, "evidence": [row["id"] for row in related]})
        elif name == "privilege" and expected in {"non_root", "unprivileged"}:
            related = [row for row in findings if any(word in row["id"] for word in ("ROOT", "PRIVILEGED"))]
            assumption_checks.append({"assumption": name, "expected": expected,
                                      "satisfied": not related, "evidence": [row["id"] for row in related]})
        else:
            assumption_checks.append({"assumption": name, "expected": expected,
                                      "satisfied": None, "evidence": []})
            unknowns.append(unknown_document("unsupported-application-assumption", source=path,
                                              details={"assumption": name}))
    if document is not None and policies:
        policy_report = check_policies(document, list(policies))
        findings.extend(policy_report["findings"])
        unknowns.extend(policy_report["unknowns"])
    for check in assumption_checks:
        if check["satisfied"] is False:
            findings.append(_finding("IAC-APPLICATION-ASSUMPTION",
                f"deployment violates application assumption {check['assumption']}", path))
    coverage_report = _parser_coverage(format, coverage, path)
    for finding in findings:
        if finding.get("kind") == "iac":
            finding["confidence"] = coverage_report["confidence"]
    return {"schema": IAC_SCHEMA, "status": "unknown" if unknowns else "ok",
            "findings": findings, "unknowns": unknowns,
            "assumption_checks": assumption_checks,
            "coverage": coverage_report}
