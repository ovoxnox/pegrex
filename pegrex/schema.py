"""Stable, versioned machine-readable documents and compatibility envelopes.

Version 1 is additive: existing report keys remain in place, while typed
findings, contracts, UNKNOWNs, and certificates gain explicit schema identity.
"""
from __future__ import annotations

import copy
import json
import re
from typing import Any

FINDING = "pegrex.finding.v1"
CONTRACT = "pegrex.contract.v1"
UNKNOWN = "pegrex.unknown.v1"
CERTIFICATE = "pegrex.certificate.v1"
CLI_ENVELOPE = "pegrex.cli-envelope.v1"


def _definition(schema: str, title: str, required: list[str], properties: dict) -> dict:
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"pegrex:{schema}:schema", "title": title, "type": "object",
        "required": required, "properties": properties, "additionalProperties": True,
    }


_STRING = {"type": "string"}
_ARRAY = {"type": "array"}
_OBJECT = {"type": "object"}
_INTEGER = {"type": "integer", "minimum": 0}
SCHEMA_DEFINITIONS = {
    FINDING: _definition(FINDING, "PegRex security finding",
        ["schema", "schema_version", "id", "severity", "confidence", "line", "evidence", "kind"], {
            "schema": {"const": FINDING}, "schema_version": {"const": 1},
            "id": _STRING, "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
            "confidence": _STRING, "line": {"type": "integer", "minimum": 1},
            "evidence": _STRING, "kind": _STRING, "file": {"type": ["string", "null"]},
            "suppressed": {"type": "boolean"}, "unknowns": _ARRAY,
        }),
    CONTRACT: _definition(CONTRACT, "PegRex observable path contract",
        ["schema", "schema_version", "constraints", "outcome"], {
            "schema": {"const": CONTRACT}, "schema_version": {"const": 1},
            "constraints": {"type": "array", "items": _STRING}, "outcome": _STRING,
            "identity": _STRING, "constraint_identity": _STRING,
            "effects": _OBJECT, "unknowns": _ARRAY,
        }),
    UNKNOWN: _definition(UNKNOWN, "PegRex explicit unknown",
        ["schema", "schema_version", "status", "reason"], {
            "schema": {"const": UNKNOWN}, "schema_version": {"const": 1},
            "status": {"const": "unknown"}, "reason": {"type": "string", "minLength": 1},
            "source": _STRING, "resource": _STRING, "details": _OBJECT,
        }),
    CERTIFICATE: _definition(CERTIFICATE, "PegRex three-valued certificate",
        ["schema", "schema_version", "verdict", "claim", "evidence", "unknowns"], {
            "schema": {"const": CERTIFICATE}, "schema_version": {"const": 1},
            "verdict": {"type": "string", "enum": ["proved", "refuted", "unknown"]},
            "claim": _STRING, "evidence": _OBJECT, "unknowns": _ARRAY,
            "counterexample": {"type": ["object", "null"]},
        }),
    CLI_ENVELOPE: _definition(CLI_ENVELOPE, "PegRex opt-in CLI result envelope",
        ["schema", "schema_version", "command", "data"], {
            "schema": {"const": CLI_ENVELOPE}, "schema_version": {"const": 1},
            "command": _STRING, "data": _OBJECT,
        }),
    "pegrex.dependency-reachability.v1": _definition("pegrex.dependency-reachability.v1", "Dependency reachability report",
        ["schema", "root", "dependencies", "summary", "coverage", "parse_failures"], {
            "schema": {"const": "pegrex.dependency-reachability.v1"}, "root": _STRING,
            "dependencies": _ARRAY, "summary": _OBJECT, "coverage": _STRING, "parse_failures": _ARRAY,
        }),
    "pegrex.policy.v1": _definition("pegrex.policy.v1", "Organization policy evaluation",
        ["schema", "policy_id", "passed", "violations", "unknown_count", "coverage_complete", "failures"], {
            "schema": {"const": "pegrex.policy.v1"}, "policy_id": _STRING,
            "passed": {"type": "boolean"}, "violations": _ARRAY, "unknown_count": _INTEGER,
            "coverage_complete": {"type": "boolean"}, "failures": _ARRAY,
        }),
    "pegrex.rule-effectiveness.v1": _definition("pegrex.rule-effectiveness.v1", "Labeled rule effectiveness metrics",
        ["schema", "rule_id", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "labeled_cases"], {
            "schema": {"const": "pegrex.rule-effectiveness.v1"}, "rule_id": _STRING,
            "tp": _INTEGER, "fp": _INTEGER, "tn": _INTEGER, "fn": _INTEGER,
            "precision": {"type": "number", "minimum": 0, "maximum": 1},
            "recall": {"type": "number", "minimum": 0, "maximum": 1},
            "f1": {"type": "number", "minimum": 0, "maximum": 1}, "labeled_cases": _INTEGER,
        }),
    "pegrex.plugin.v1": _definition("pegrex.plugin.v1", "Plugin SDK conformance result",
        ["schema", "passed", "tests", "errors"], {
            "schema": {"const": "pegrex.plugin.v1"}, "passed": {"type": "boolean"},
            "tests": _INTEGER, "errors": _ARRAY,
        }),
    "pegrex.security-analysis.v1": _definition("pegrex.security-analysis.v1", "Security analysis result",
        ["schema", "findings", "unknowns", "coverage"], {
            "schema": {"const": "pegrex.security-analysis.v1"}, "findings": _ARRAY,
            "unknowns": _ARRAY, "coverage": _OBJECT,
        }),
    "pegrex.patch-review.v1": _definition("pegrex.patch-review.v1", "Evidence-backed patch review",
        ["schema", "verdict", "verified_properties", "counterexample", "unresolved_obligations", "provenance"], {
            "schema": {"const": "pegrex.patch-review.v1"}, "verdict": {"enum": ["proved", "refuted", "unknown", "ok"]},
            "verified_properties": _ARRAY, "counterexample": {"type": ["object", "null"]},
            "unresolved_obligations": _ARRAY, "provenance": _OBJECT,
        }),
    "pegrex.repair-loop.v1": _definition("pegrex.repair-loop.v1", "Repair candidate evaluation result",
        ["schema", "status", "results", "unknowns"], {
            "schema": {"const": "pegrex.repair-loop.v1"}, "status": _STRING,
            "results": _ARRAY, "unknowns": _ARRAY,
        }),
    "pegrex.agent-context.v1": _definition("pegrex.agent-context.v1", "Evidence-preserving agent context",
        ["schema", "items", "truncated", "sha256"], {
            "schema": {"const": "pegrex.agent-context.v1"}, "items": _OBJECT,
            "truncated": _OBJECT, "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        }),
    "pegrex.iac-audit.v1": _definition("pegrex.iac-audit.v1", "Infrastructure-as-code audit result",
        ["schema", "file", "findings", "coverage", "unknowns"], {
            "schema": {"const": "pegrex.iac-audit.v1"}, "file": _STRING,
            "findings": _ARRAY, "coverage": _STRING, "unknowns": _ARRAY,
        }),
    "pegrex.rule-mutation.v1": _definition("pegrex.rule-mutation.v1", "Rule mutation effectiveness result",
        ["schema", "mutants", "killed", "survived", "interpretable"], {
            "schema": {"const": "pegrex.rule-mutation.v1"}, "mutants": _INTEGER,
            "killed": _INTEGER, "survived": _INTEGER, "interpretable": {"type": "boolean"},
        }),
    "pegrex.security-regression-fixture.v1": _definition("pegrex.security-regression-fixture.v1", "Confirmed security regression fixture",
        ["schema", "id", "severity", "rule_id", "witness", "expected", "review_required"], {
            "schema": {"const": "pegrex.security-regression-fixture.v1"}, "id": _STRING,
            "severity": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]}, "rule_id": _STRING,
            "witness": _OBJECT, "expected": {"const": "detect"}, "review_required": {"const": True},
        }),
    "pegrex.high-severity-mutation-audit.v1": _definition("pegrex.high-severity-mutation-audit.v1", "High severity rule mutation audit",
        ["schema", "rules_checked", "measured", "results"], {
            "schema": {"const": "pegrex.high-severity-mutation-audit.v1"}, "rules_checked": _INTEGER,
            "measured": _INTEGER, "results": _ARRAY,
        }),
    "pegrex.iac-app-correlation.v1": _definition("pegrex.iac-app-correlation.v1", "Application assumption and IaC correlation",
        ["schema", "conflicts", "coverage", "unknowns"], {
            "schema": {"const": "pegrex.iac-app-correlation.v1"}, "conflicts": _ARRAY,
            "coverage": _STRING, "unknowns": _ARRAY,
        }),
}


# Public result schemas that were previously emitted by APIs without a catalog entry.
# For legacy records whose full nested contract is not yet stabilized, the schema
# deliberately validates the versioned envelope only; metadata marks that limit.
_PUBLIC_RESULT_SCHEMA_IDS = [
    'pegrex.a2a-task.v1',
    'pegrex.action-evidence-attestation.v1',
    'pegrex.agent-action-authorization.v1',
    'pegrex.agent-action-evidence.v1',
    'pegrex.agent-action-plan.v1',
    'pegrex.agent-context.v1',
    'pegrex.agent-evidence.v1',
    'pegrex.agent-repair-differential.v1',
    'pegrex.agent-role-evidence.v1',
    'pegrex.agent-tools.v1',
    'pegrex.analysis-session.v1',
    'pegrex.analyzer-mutation.v1',
    'pegrex.analyzer-worker.v1',
    'pegrex.api-round-trip.v1',
    'pegrex.architecture-drift.v1',
    'pegrex.assurance-query.v1',
    'pegrex.attack-path-graph.v1',
    'pegrex.bounded-model-check.v1',
    'pegrex.canonical-constraints.v1',
    'pegrex.capsule-sandbox-recipe.v1',
    'pegrex.certificate.v1',
    'pegrex.change-impact-simulation.v1',
    'pegrex.cli-envelope.v1',
    'pegrex.cli-error.v1',
    'pegrex.compiler-differential.v1',
    'pegrex.compiler-ir.v1',
    'pegrex.compliance-evidence-pack.v1',
    'pegrex.compliance-map-query.v1',
    'pegrex.compositional-verification.v1',
    'pegrex.concurrency-analysis.v1',
    'pegrex.continuous-assurance-graph.v1',
    'pegrex.contract-modernization.v1',
    'pegrex.contract-subsumption.v1',
    'pegrex.contract.v1',
    'pegrex.core-engine.v1',
    'pegrex.core-operations.v2',
    'pegrex.core.v1',
    'pegrex.counterexample-minimization.v1',
    'pegrex.decision-provenance.v1',
    'pegrex.dependency-reachability.v1',
    'pegrex.edit-audit.v1',
    'pegrex.edit-decision.v1',
    'pegrex.effects.v1',
    'pegrex.executable-compliance-map.v1',
    'pegrex.exploitability-evidence.v1',
    'pegrex.finding.v1',
    'pegrex.finite-domain-proof.v1',
    'pegrex.formal-protocol.v1',
    'pegrex.function-contracts.v1',
    'pegrex.function-summary.v1',
    'pegrex.harness-policy-tests.v1',
    'pegrex.health-dispositions.v1',
    'pegrex.high-severity-mutation-audit.v1',
    'pegrex.hybrid-priority.v1',
    'pegrex.iac-analysis.v1',
    'pegrex.iac-app-correlation.v1',
    'pegrex.iac-audit.v1',
    'pegrex.incident-replay.v1',
    'pegrex.incremental-contracts-state.v1',
    'pegrex.incremental-contracts.v1',
    'pegrex.integration-request.v1',
    'pegrex.integration-result.v1',
    'pegrex.interprocedural-summaries.v1',
    'pegrex.interprocedural-taint.v1',
    'pegrex.ironkernel-worker.v1',
    'pegrex.kernel-check.v1',
    'pegrex.language-capabilities.v1',
    'pegrex.lockfile-policy.v1',
    'pegrex.loop-invariants.v1',
    'pegrex.memory-graph.v1',
    'pegrex.multi-agent-change.v1',
    'pegrex.mutation-testing.v1',
    'pegrex.neural-codegen-adapter-build.v1',
    'pegrex.neural-codegen-backend.v1',
    'pegrex.normalized-semantic-payload.v1',
    'pegrex.observability-twin.v1',
    'pegrex.osv-provenance.v1',
    'pegrex.osv-scan.v1',
    'pegrex.osv-snapshot.v1',
    'pegrex.patch-explanation.v1',
    'pegrex.patch-gate.v1',
    'pegrex.patch-review.v1',
    'pegrex.path-contract-validation.v1',
    'pegrex.path-contract.v2',
    'pegrex.path-refinement.v1',
    'pegrex.plugin-worker.v1',
    'pegrex.plugin.v1',
    'pegrex.poc-execution.v1',
    'pegrex.policy-build-gate.v1',
    'pegrex.policy-checks.v1',
    'pegrex.policy.v1',
    'pegrex.proof-carrying-release.v1',
    'pegrex.proof-guided-fuzz.v1',
    'pegrex.proof-replay.v1',
    'pegrex.protocol-model-check.v1',
    'pegrex.prover-bridge.v1',
    'pegrex.pythoc-worker.v1',
    'pegrex.reachability-sca.v1',
    'pegrex.regression-network.v1',
    'pegrex.release-api-contracts.v1',
    'pegrex.release-semantic-diff.v1',
    'pegrex.release-unknown-summary.v1',
    'pegrex.repair-loop.v1',
    'pegrex.repair-recheck.v1',
    'pegrex.repository-digital-twin.v1',
    'pegrex.repository-immune.v1',
    'pegrex.repository-index-state.v1',
    'pegrex.repository-index.v1',
    'pegrex.repository-memory.v1',
    'pegrex.reproducible-audit-bundle.v1',
    'pegrex.resource-bounds.v1',
    'pegrex.risk-aware-change-plan.v1',
    'pegrex.rule-effectiveness.v1',
    'pegrex.rule-mutation.v1',
    'pegrex.sandboxed-differential.v1',
    'pegrex.scan-coverage-set.v1',
    'pegrex.scan-coverage.v1',
    'pegrex.security-analysis.v1',
    'pegrex.security-contract.v1',
    'pegrex.security-effectiveness-benchmark.v1',
    'pegrex.security-evaluation.v1',
    'pegrex.security-policy-decision.v1',
    'pegrex.security-provenance-set.v1',
    'pegrex.security-provenance.v1',
    'pegrex.security-regression-fixture.v1',
    'pegrex.security-regression-memory.v1',
    'pegrex.security-research-capsule.v1',
    'pegrex.security-scan-set.v1',
    'pegrex.security-scan.v1',
    'pegrex.semantic-change-budget.v1',
    'pegrex.semantic-checksum-diff.v1',
    'pegrex.semantic-checksum.v1',
    'pegrex.semantic-dependency-graph.v1',
    'pegrex.smart-contract-evidence.v1',
    'pegrex.smtlib-export.v1',
    'pegrex.soundness.v1',
    'pegrex.spec-proposal.v1',
    'pegrex.ssa.v1',
    'pegrex.state-profile.v1',
    'pegrex.taint-framework-packs.v1',
    'pegrex.taint-summary.v1',
    'pegrex.test-promotion.v1',
    'pegrex.tools-api-envelope.v2',
    'pegrex.tools-api-manifest.v2',
    'pegrex.trace-guided-paths.v1',
    'pegrex.unknown.v1',
]
for _public_schema_id in _PUBLIC_RESULT_SCHEMA_IDS:
    if _public_schema_id == "pegrex.interprocedural-taint.v1":
        SCHEMA_DEFINITIONS[_public_schema_id] = _definition(
            _public_schema_id, "Interprocedural taint analysis result",
            ["schema", "fixed_point", "summaries", "findings", "unknowns"], {
                "schema": {"const": _public_schema_id}, "fixed_point": _OBJECT,
                "summaries": _OBJECT, "findings": _ARRAY, "unknowns": _ARRAY})
    elif _public_schema_id == "pegrex.security-effectiveness-benchmark.v1":
        SCHEMA_DEFINITIONS[_public_schema_id] = _definition(
            _public_schema_id, "Security rule effectiveness benchmark",
            ["schema", "model_version", "cases", "categories", "metrics", "high_severity_mutation_audit", "case_results", "errors", "limitations"], {
                "schema": {"const": _public_schema_id}, "model_version": _STRING,
                "cases": _INTEGER, "categories": _INTEGER, "metrics": _ARRAY,
                "high_severity_mutation_audit": _OBJECT, "case_results": _ARRAY,
                "errors": _ARRAY, "limitations": _ARRAY})
    elif _public_schema_id not in SCHEMA_DEFINITIONS:
        SCHEMA_DEFINITIONS[_public_schema_id] = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"pegrex:{_public_schema_id}:schema",
            "title": f"PegRex public result envelope: {_public_schema_id}",
            "type": "object", "required": ["schema"],
            "properties": {"schema": {"const": _public_schema_id}},
            "additionalProperties": True,
            "x-peg-rex-validation-level": "envelope-only; nested contract pending stabilization"}

SCHEMA_DEFINITIONS["pegrex.plugin-worker.v1"] = _definition(
    "pegrex.plugin-worker.v1", "Restricted plugin worker result",
    ["schema", "status"], {
        "schema": {"const": "pegrex.plugin-worker.v1"},
        "status": {"enum": ["ok", "unknown"]}, "reason": _STRING,
        "result": _OBJECT, "containerized": {"type": "boolean"},
        "network_disabled": {"type": "boolean"},
        "read_only_plugin_mount": {"type": "boolean"},
        "exit_code": {"type": "integer"}, "stderr_bytes": _INTEGER})

# Packaged JSON Schema files are authoritative for the wire-level constraints.
# Loading them here keeps the programmatic catalog aligned with the published
# schemas, including conditional certificate constraints.
from pathlib import Path as _SchemaPath
_SCHEMA_DIR = _SchemaPath(__file__).with_name("jsonschemas")
for _schema_file in _SCHEMA_DIR.glob("*.json"):
    try:
        _schema_doc = json.loads(_schema_file.read_text(encoding="utf-8"))
        _schema_key = _schema_doc.get("properties", {}).get("schema", {}).get("const")
        if isinstance(_schema_key, str):
            SCHEMA_DEFINITIONS[_schema_key] = _schema_doc
    except (OSError, ValueError, AttributeError):
        continue


def _document(schema: str, payload: dict[str, Any], **extra) -> dict:
    if not isinstance(payload, dict):
        raise TypeError(f"{schema} payload must be an object")
    result = dict(payload)
    result.update(extra)
    result["schema"] = schema
    result["schema_version"] = 1
    require_valid(result)
    return result


def finding_document(finding: dict[str, Any]) -> dict:
    """Implement finding document with the module's explicit API and failure semantics."""
    return _document(FINDING, finding)


def contract_document(contract: dict[str, Any] | None = None, *, constraints=(),
                      outcome: str | None = None, **metadata) -> dict:
    """Implement contract document with the module's explicit API and failure semantics."""
    payload = dict(contract or {})
    if contract is None or "constraints" in metadata or outcome is not None:
        payload["constraints"] = sorted(map(str, metadata.pop("constraints", constraints)))
    if outcome is not None:
        payload["outcome"] = str(outcome)
    payload.update(metadata)
    return _document(CONTRACT, payload)


def unknown_document(reason: str, *, source: str | None = None,
                     resource: str | None = None, details: dict | None = None) -> dict:
    """Implement unknown document with the module's explicit API and failure semantics."""
    payload = {"status": "unknown", "reason": str(reason)}
    if source is not None:
        payload["source"] = source
    if resource is not None:
        payload["resource"] = resource
    if details is not None:
        payload["details"] = details
    return _document(UNKNOWN, payload)


def certificate_document(verdict: str, claim: str, *, evidence: dict | None = None,
                         unknowns=(), counterexample: dict | None = None, **metadata) -> dict:
    """Implement certificate document with the module's explicit API and failure semantics."""
    return _document(CERTIFICATE, metadata, verdict=verdict, claim=claim,
                     evidence=evidence or {}, unknowns=list(unknowns),
                     counterexample=counterexample)


def cli_envelope(command: str, data: dict) -> dict:
    """Implement cli envelope with the module's explicit API and failure semantics."""
    return _document(CLI_ENVELOPE, {"command": command, "data": data})



# Manually reviewed high-value result contracts. These override AST-inferred
# shapes so consumers can validate nested evidence and coverage fields.
SCHEMA_DEFINITIONS["pegrex.security-analysis.v1"] = _definition(
    "pegrex.security-analysis.v1", "Security analysis result",
    ["schema", "findings", "unknowns", "coverage"], {
        "schema": {"const": "pegrex.security-analysis.v1"},
        "analysis_schema": {"type": ["string", "null"]},
        "findings": {"type": "array", "items": {"type": "object", "required": ["id"],
            "properties": {"id": _STRING, "rule_id": _STRING, "severity": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                           "confidence": _STRING, "file": _STRING, "line": {"type": "integer", "minimum": 1},
                           "evidence": _STRING, "source": _STRING, "sink": _STRING, "flow": _ARRAY,
                           "unknowns": {"type": "array", "items": _STRING}}, "additionalProperties": True}},
        "unknowns": {"type": "array", "items": _STRING},
        "coverage": {"type": "object", "required": ["status"], "properties": {
            "status": {"enum": ["complete", "partial", "unknown"]}, "language": _STRING,
            "mode": {"enum": ["fast", "deep"]}, "model_version": _STRING,
            "limits": {"type": "array", "items": _STRING}}, "additionalProperties": True},
        "security_model": _STRING, "resource_usage": {"type": "object", "additionalProperties": True},
    })
SCHEMA_DEFINITIONS["pegrex.iac-audit.v1"] = _definition(
    "pegrex.iac-audit.v1", "Infrastructure-as-code audit result",
    ["schema", "file", "findings", "coverage", "unknowns"], {
        "schema": {"const": "pegrex.iac-audit.v1"}, "file": _STRING,
        "findings": {"type": "array", "items": {"type": "object", "required": ["kind"],
            "properties": {"kind": _STRING, "severity": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
                           "line": {"type": "integer", "minimum": 1}, "evidence": _STRING,
                           "resource": _STRING, "message": _STRING}, "additionalProperties": True}},
        "coverage": {"type": "string", "minLength": 1},
        "unknowns": {"type": "array", "items": _STRING},
    })
SCHEMA_DEFINITIONS["pegrex.security-scan.v1"] = _definition(
    "pegrex.security-scan.v1", "Security scan result",
    ["schema", "file", "findings", "coverage", "unknowns"], {
        "schema": {"const": "pegrex.security-scan.v1"}, "file": _STRING,
        "findings": {"type": "array", "items": {"type": "object", "properties": {
            "id": _STRING, "rule_id": _STRING, "severity": {"enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]},
            "line": {"type": "integer", "minimum": 1}, "evidence": _STRING, "suppressed": {"type": "boolean"}},
            "required": ["id"], "additionalProperties": True}},
        "coverage": {"type": "object", "additionalProperties": True},
        "unknowns": {"type": "array", "items": _STRING},
        "language": _STRING, "mode": {"enum": ["fast", "deep"]},
        "total": _INTEGER, "active_total": _INTEGER, "suppressed_total": _INTEGER,
        "resource_limits": {"type": "object", "additionalProperties": True},
        "provenance": {"type": "object", "additionalProperties": True},
    })
SCHEMA_DEFINITIONS["pegrex.security-effectiveness-benchmark.v1"] = _definition(
    "pegrex.security-effectiveness-benchmark.v1", "Security rule effectiveness benchmark",
    ["schema", "model_version", "cases", "metrics", "high_severity_mutation_audit", "case_results", "errors", "limitations"], {
        "schema": {"const": "pegrex.security-effectiveness-benchmark.v1"}, "model_version": _STRING,
        "cases": _INTEGER, "categories": _INTEGER,
        "metrics": {"type": "array", "items": {"type": "object", "required": ["rule_id", "tp", "fp", "tn", "fn", "precision", "recall", "f1"],
            "properties": {"rule_id": _STRING, "tp": _INTEGER, "fp": _INTEGER, "tn": _INTEGER, "fn": _INTEGER,
                           "precision": {"type": "number", "minimum": 0, "maximum": 1},
                           "recall": {"type": "number", "minimum": 0, "maximum": 1},
                           "f1": {"type": "number", "minimum": 0, "maximum": 1}, "coverage": {"type": "number", "minimum": 0, "maximum": 1}},
            "additionalProperties": True}},
        "high_severity_mutation_audit": {"type": "object", "additionalProperties": True},
        "case_results": {"type": "array", "items": {"type": "object", "required": ["id", "expected_vulnerable", "detected"],
            "properties": {"id": _STRING, "expected_vulnerable": {"type": "boolean"}, "detected": {"type": "boolean"}},
            "additionalProperties": True}},
        "errors": {"type": "array"}, "limitations": {"type": "array", "items": _STRING},
    })
SCHEMA_DEFINITIONS["pegrex.rule-effectiveness.v1"] = _definition(
    "pegrex.rule-effectiveness.v1", "Labeled rule effectiveness metrics",
    ["schema", "rule_id", "tp", "fp", "tn", "fn", "precision", "recall", "f1", "labeled_cases"], {
        "schema": {"const": "pegrex.rule-effectiveness.v1"}, "rule_id": _STRING,
        "tp": _INTEGER, "fp": _INTEGER, "tn": _INTEGER, "fn": _INTEGER,
        "precision": {"type": "number", "minimum": 0, "maximum": 1},
        "recall": {"type": "number", "minimum": 0, "maximum": 1},
        "f1": {"type": "number", "minimum": 0, "maximum": 1}, "coverage": {"type": "number", "minimum": 0, "maximum": 1},
        "labeled_cases": _INTEGER, "errors": _INTEGER,
        "results": {"type": "array", "items": {"type": "object", "required": ["expected", "actual"],
            "properties": {"expected": {"type": "boolean"}, "actual": {"type": ["boolean", "null"]},
                           "correct": {"type": "boolean"}, "id": _STRING}, "additionalProperties": True}},
    })
SCHEMA_DEFINITIONS["pegrex.plugin-worker.v1"] = _definition(
    "pegrex.plugin-worker.v1", "Restricted plugin worker result",
    ["schema", "status"], {
        "schema": {"const": "pegrex.plugin-worker.v1"}, "status": {"enum": ["ok", "unknown"]},
        "reason": _STRING, "containerized": {"type": "boolean"}, "network_disabled": {"type": "boolean"},
        "read_only_plugin_mount": {"type": "boolean"}, "result": {"type": "object"},
        "exit_code": {"type": "integer"}, "stderr_bytes": _INTEGER,
    })



# Additional manually reviewed schemas for high-value cross-component contracts.
SCHEMA_DEFINITIONS["pegrex.security-scan-set.v1"] = _definition(
    "pegrex.security-scan-set.v1", "Multi-file security scan result",
    ["schema", "files", "findings", "unknowns", "coverage", "total", "active_total", "suppressed_total"], {
        "schema": {"const": "pegrex.security-scan-set.v1"},
        "files": {"type": "array", "items": {"type": "object", "required": ["file"],
            "properties": {"file": _STRING, "findings": {"type": "array"}, "unknowns": {"type": "array"}}, "additionalProperties": True}},
        "findings": {"type": "array", "items": {"type": "object", "required": ["id"], "properties": {"id": _STRING, "severity": _STRING}, "additionalProperties": True}},
        "unknowns": {"type": "array", "items": _STRING}, "coverage": {"type": "object", "additionalProperties": True},
        "total": _INTEGER, "active_total": _INTEGER, "suppressed_total": _INTEGER,
        "provenance": {"type": "object", "additionalProperties": True},
    })
SCHEMA_DEFINITIONS["pegrex.security-provenance.v1"] = _definition(
    "pegrex.security-provenance.v1", "Security analysis provenance",
    ["schema", "source", "language", "parser", "configuration", "rules"], {
        "schema": {"const": "pegrex.security-provenance.v1"}, "source": {"type": "object", "additionalProperties": True},
        "language": _STRING, "parser": {"type": "object", "additionalProperties": True},
        "configuration": {"type": "object", "additionalProperties": True},
        "rules": {"type": "object", "additionalProperties": True}, "osv": {"type": ["object", "null"]},
    })
SCHEMA_DEFINITIONS["pegrex.security-provenance-set.v1"] = _definition(
    "pegrex.security-provenance-set.v1", "Security scan provenance set",
    ["schema", "sources"], {"schema": {"const": "pegrex.security-provenance-set.v1"},
        "sources": {"type": "array", "items": {"type": "object", "required": ["source"],
            "properties": {"source": {"type": "object", "additionalProperties": True}}, "additionalProperties": True}}})
SCHEMA_DEFINITIONS["pegrex.taint-summary.v1"] = _definition(
    "pegrex.taint-summary.v1", "Taint summary result",
    ["schema", "summaries", "findings", "unknowns"], {"schema": {"const": "pegrex.taint-summary.v1"},
        "summaries": {"type": "object", "additionalProperties": {"type": "object", "additionalProperties": True}},
        "findings": {"type": "array", "items": {"type": "object", "additionalProperties": True}},
        "unknowns": {"type": "array", "items": _STRING}, "fixed_point": {"type": "object", "additionalProperties": True}})
SCHEMA_DEFINITIONS["pegrex.language-capabilities.v1"] = _definition(
    "pegrex.language-capabilities.v1", "Language capability registry result",
    ["schema", "languages"], {"schema": {"const": "pegrex.language-capabilities.v1"},
        "languages": {"type": "array", "items": {"type": "object", "required": ["id"],
            "properties": {"id": _STRING, "name": _STRING, "status": _STRING, "features": {"type": "object", "additionalProperties": {"type": "boolean"}},
                           "limitations": {"type": "array", "items": _STRING}}, "additionalProperties": True}}})
SCHEMA_DEFINITIONS["pegrex.analysis-session.v1"] = _definition(
    "pegrex.analysis-session.v1", "Analysis session budget and accounting result",
    ["schema", "language", "mode", "source_sha256", "resource_limits", "profile", "solver_budget", "results"], {
        "schema": {"const": "pegrex.analysis-session.v1"}, "language": _STRING,
        "mode": {"enum": ["fast", "deep", "default"]},
        "source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "resource_limits": {"type": "object", "required": ["max_paths", "max_source_bytes", "max_ast_nodes", "max_output_bytes", "max_solver_calls"], "properties": {"timeout_ms": {"type": ["integer", "null"]}, "max_paths": _INTEGER, "max_source_bytes": _INTEGER, "max_ast_nodes": _INTEGER, "max_output_bytes": _INTEGER, "max_solver_calls": _INTEGER}, "additionalProperties": True},
        "profile": {"type": "object", "required": ["counters"], "properties": {"counters": {"type": "object", "additionalProperties": {"type": "integer", "minimum": 0}}}, "additionalProperties": True},
        "solver_budget": {"type": "object", "required": ["max_calls", "calls"], "properties": {"max_calls": _INTEGER, "calls": _INTEGER}, "additionalProperties": True},
        "results": {"type": "object", "additionalProperties": {"type": "object", "required": ["status"], "properties": {"status": {"enum": ["ok", "unknown"]}, "data": {}, "reason": _STRING, "resource": _STRING}, "additionalProperties": True}},
    })
SCHEMA_DEFINITIONS["pegrex.schema-catalog-audit.v1"] = _definition(
    "pegrex.schema-catalog-audit.v1", "Public schema catalog consistency audit",
    ["schema", "files", "catalog_entries", "levels", "errors", "passed", "limitations"], {
        "schema": {"const": "pegrex.schema-catalog-audit.v1"}, "files": _INTEGER, "catalog_entries": _INTEGER,
        "levels": {"type": "object", "additionalProperties": _INTEGER}, "errors": {"type": "array", "items": _STRING},
        "passed": {"type": "boolean"}, "limitations": {"type": "array", "items": _STRING}})
SCHEMA_DEFINITIONS["pegrex.repository-memory.v1"] = _definition(
    "pegrex.repository-memory.v1", "Versioned repository memory result",
    ["schema", "entries", "unknowns", "status"], {"schema": {"const": "pegrex.repository-memory.v1"},
        "entries": {"type": "array", "items": {"type": "object", "required": ["id"],
            "properties": {"id": _STRING, "kind": _STRING, "source_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                           "evidence": {"type": "array"}, "constraints": {"type": "array"}}, "additionalProperties": True}},
        "unknowns": {"type": "array", "items": _STRING}, "status": _STRING, "schema_version": {"const": 1}})
SCHEMA_DEFINITIONS["pegrex.security-regression-memory.v1"] = _definition(
    "pegrex.security-regression-memory.v1", "Security regression memory result",
    ["schema", "entries", "status", "unknowns"], {"schema": {"const": "pegrex.security-regression-memory.v1"},
        "entries": {"type": "array", "items": {"type": "object", "required": ["rule_id", "fixture"],
            "properties": {"rule_id": _STRING, "fixture": {"type": "object", "additionalProperties": True}, "review_required": {"type": "boolean"}}, "additionalProperties": True}},
        "status": _STRING, "unknowns": {"type": "array", "items": _STRING}, "schema_version": {"const": 1}})
SCHEMA_DEFINITIONS["pegrex.resource-bounds.v1"] = _definition(
    "pegrex.resource-bounds.v1", "Resource budget report",
    ["schema", "limits", "usage", "exhausted", "unknowns"], {"schema": {"const": "pegrex.resource-bounds.v1"},
        "limits": {"type": "object", "additionalProperties": {"type": ["integer", "number", "string", "boolean", "null"]}},
        "usage": {"type": "object", "additionalProperties": {"type": ["integer", "number", "string", "boolean", "null"]}},
        "exhausted": {"type": "boolean"}, "unknowns": {"type": "array", "items": _STRING}})
SCHEMA_DEFINITIONS["pegrex.agent-action-plan.v1"] = _definition(
    "pegrex.agent-action-plan.v1", "Agent action plan",
    ["schema", "actions", "status", "unknowns"], {"schema": {"const": "pegrex.agent-action-plan.v1"},
        "actions": {"type": "array", "items": {"type": "object", "required": ["id"],
            "properties": {"id": _STRING, "tool": _STRING, "arguments": {"type": "object"}, "risk": _STRING, "requires_approval": {"type": "boolean"}}, "additionalProperties": True}},
        "status": _STRING, "unknowns": {"type": "array", "items": _STRING}, "schema_version": {"const": 1}})


def schema_catalog() -> dict:
    """Return independent JSON Schema documents, safe to serialize or modify."""
    return copy.deepcopy(SCHEMA_DEFINITIONS)


def validate_document(document: dict) -> list[str]:
    """Validate a public result against its registered JSON Schema.

    This compact validator supports the schema keywords used by PegRex's
    published contracts, including nested properties/items and closed objects.
    It intentionally rejects recursion deeper than 64 levels.
    """
    if not isinstance(document, dict):
        return ["document must be a JSON object"]
    schema_id = document.get("schema")
    definition = SCHEMA_DEFINITIONS.get(schema_id)
    if definition is None:
        return [f"unsupported or missing schema {schema_id!r}"]

    def check(value, rule, path, depth=0):
        errors = []
        if depth > 64:
            return [f"{path}: maximum schema validation depth exceeded"]
        for subschema in rule.get("allOf", []):
            errors.extend(check(value, subschema, path, depth + 1))
        if "anyOf" in rule:
            alternatives = [check(value, subschema, path, depth + 1) for subschema in rule["anyOf"]]
            if not any(not candidate for candidate in alternatives):
                errors.append(f"{path}: does not match anyOf alternatives")
        if "oneOf" in rule:
            alternatives = [check(value, subschema, path, depth + 1) for subschema in rule["oneOf"]]
            if sum(not candidate for candidate in alternatives) != 1:
                errors.append(f"{path}: does not match exactly one oneOf alternative")
        condition = rule.get("if")
        if isinstance(condition, dict):
            condition_errors = check(value, condition, path, depth + 1)
            branch = rule.get("then") if not condition_errors else rule.get("else")
            if isinstance(branch, dict):
                errors.extend(check(value, branch, path, depth + 1))
        if "const" in rule and value != rule["const"]:
            errors.append(f"{path}: expected {rule['const']!r}")
        if "enum" in rule and value not in rule["enum"]:
            errors.append(f"{path}: expected one of {rule['enum']!r}")
        expected = rule.get("type")
        types = expected if isinstance(expected, list) else [expected]
        type_map = {"string": str, "object": dict, "array": list, "boolean": bool, "null": type(None), "number": (int, float), "integer": int}
        if expected:
            valid = False
            for kind in types:
                cls = type_map.get(kind)
                if cls is None:
                    continue
                if kind in {"integer", "number"}:
                    match = isinstance(value, cls) and not isinstance(value, bool)
                    if kind == "integer": match = match and not isinstance(value, bool)
                else:
                    match = isinstance(value, cls)
                if match: valid = True; break
            if not valid:
                errors.append(f"{path}: expected JSON type {expected}")
                return errors
        if isinstance(value, str):
            if "minLength" in rule and len(value) < rule["minLength"]: errors.append(f"{path}: shorter than minLength")
            if "maxLength" in rule and len(value) > rule["maxLength"]: errors.append(f"{path}: longer than maxLength")
            if "pattern" in rule and re.search(rule["pattern"], value) is None: errors.append(f"{path}: does not match pattern")
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in rule and value < rule["minimum"]: errors.append(f"{path}: below minimum")
            if "maximum" in rule and value > rule["maximum"]: errors.append(f"{path}: above maximum")
        if isinstance(value, list):
            if "minItems" in rule and len(value) < rule["minItems"]: errors.append(f"{path}: fewer than minItems")
            if "maxItems" in rule and len(value) > rule["maxItems"]: errors.append(f"{path}: more than maxItems")
            item_rule = rule.get("items")
            if isinstance(item_rule, dict):
                for index, item in enumerate(value): errors.extend(check(item, item_rule, f"{path}[{index}]", depth+1))
        if isinstance(value, dict):
            for key in rule.get("required", []):
                if key not in value: errors.append(f"{path}: missing required property {key!r}")
            properties = rule.get("properties", {})
            for key, child in properties.items():
                if key in value: errors.extend(check(value[key], child, f"{path}.{key}", depth+1))
            additional = rule.get("additionalProperties", True)
            for key, child_value in value.items():
                if key in properties: continue
                if additional is False: errors.append(f"{path}: unsupported property {key!r}")
                elif isinstance(additional, dict): errors.extend(check(child_value, additional, f"{path}.{key}", depth+1))
        return errors

    errors = check(document, definition, "$", 0)
    if schema_id == CERTIFICATE and not errors:
        if document["verdict"] == "proved" and document["unknowns"]:
            errors.append("proved certificate cannot contain UNKNOWNs")
        if document["verdict"] == "refuted":
            witness = document.get("counterexample")
            if not isinstance(witness, dict) or witness.get("confirmed") is not True:
                errors.append("refuted certificate requires a confirmed counterexample")
    return errors


def require_valid(document: dict) -> None:
    """Implement require valid with the module's explicit API and failure semantics."""
    errors = validate_document(document)
    if errors:
        raise ValueError("invalid versioned document: " + "; ".join(errors))


def write_schema_catalog(directory) -> list[str]:
    """Implement write schema catalog with the module's explicit API and failure semantics."""
    from pathlib import Path
    destination = Path(directory)
    destination.mkdir(parents=True, exist_ok=True)
    written = []
    for schema, definition in sorted(SCHEMA_DEFINITIONS.items()):
        name = schema.removeprefix("pegrex.") + ".json"
        path = destination / name
        path.write_text(json.dumps(definition, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8")
        written.append(str(path))
    return written
