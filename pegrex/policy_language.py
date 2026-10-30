"""Small declarative organization policy language (JSON-compatible YAML subset)."""
from __future__ import annotations
import json
from pathlib import Path

POLICY_SCHEMA = "pegrex.policy.v1"
_ALLOWED = {"id", "description", "severity_at_least", "fail_on_unknown", "require_coverage", "deny_rules", "allow_rules", "max_findings"}
_SEVERITY = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def load_policy(value) -> dict:
    if isinstance(value, (str, Path)):
        if isinstance(value, Path):
            raw = value.read_text(encoding="utf-8")
        elif isinstance(value, str):
            try:
                candidate = Path(value)
                raw = candidate.read_text(encoding="utf-8") if "\n" not in value and candidate.is_file() else value
            except OSError:
                raw = value
        else:
            raw = str(value)
        try: doc = json.loads(raw)
        except json.JSONDecodeError:
            try:
                import yaml
                doc = yaml.safe_load(raw)
            except ImportError as exc:
                raise ValueError("policy is not JSON and PyYAML is unavailable") from exc
    else: doc = value
    if not isinstance(doc, dict): raise ValueError("policy must be an object")
    if doc.get("schema") == POLICY_SCHEMA:
        doc = {key: value for key, value in doc.items() if key != "schema"}
    unknown = set(doc) - _ALLOWED
    if unknown: raise ValueError("unsupported policy keys: " + ", ".join(sorted(unknown)))
    if not isinstance(doc.get("id"), str) or not doc["id"].strip(): raise ValueError("policy requires a non-empty id")
    severity = str(doc.get("severity_at_least", "HIGH")).upper()
    if severity not in _SEVERITY: raise ValueError("invalid severity_at_least")
    for key in ("deny_rules", "allow_rules"):
        if key in doc and (not isinstance(doc[key], list) or not all(isinstance(x, str) for x in doc[key])): raise ValueError(f"{key} must be a list of rule IDs")
    return {"schema": POLICY_SCHEMA, "severity_at_least": severity, "fail_on_unknown": False,
            "require_coverage": False, "deny_rules": [], "allow_rules": [], "max_findings": None, **doc}


def evaluate_policy(policy, findings, *, unknowns=(), coverage_complete=True) -> dict:
    p = load_policy(policy)
    allowed, denied = set(p["allow_rules"]), set(p["deny_rules"])
    threshold = _SEVERITY[p["severity_at_least"]]
    violations = []
    for finding in findings:
        rule = str(finding.get("rule_id") or finding.get("id") or "")
        severity = _SEVERITY.get(str(finding.get("severity", "INFO")).upper(), 0)
        if rule in allowed: continue
        if rule in denied or severity >= threshold:
            violations.append({"rule_id": rule, "severity": str(finding.get("severity", "INFO")).upper(), "file": finding.get("file"), "line": finding.get("line")})
    failures = []
    if p["fail_on_unknown"] and unknowns: failures.append("unknowns present")
    if p["require_coverage"] and not coverage_complete: failures.append("coverage incomplete")
    if p["max_findings"] is not None and len(violations) > int(p["max_findings"]): failures.append("finding limit exceeded")
    return {"schema": POLICY_SCHEMA, "policy_id": p["id"], "passed": not violations and not failures,
            "violations": violations, "unknown_count": len(unknowns), "coverage_complete": bool(coverage_complete), "failures": failures}
