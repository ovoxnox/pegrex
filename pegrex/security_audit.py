"""Composed security analysis entry point for framework flows and IaC."""
from __future__ import annotations
import json
import time
from pathlib import Path
from .flow import DEFAULT_SOURCES, DEFAULT_SINKS, analyze_modules, analyze_secrets
from .framework_models import FRAMEWORK_SOURCES, FRAMEWORK_SINKS, MODEL_VERSION
from .iac import audit_policy, audit_terraform


def analyze_security_source(source: str, *, path="<memory>.py", module="memory",
                            mode: str = "fast", max_source_bytes: int = 1_000_000) -> dict:
    """Analyze a Python source string under an explicit fast/deep resource profile.

    ``fast`` is bounded for interactive feedback; ``deep`` allows more fixed-point
    work. Limits are enforced at this entry point and inside the taint engine.
    A resource refusal is reported as UNKNOWN/partial, never as a clean result.
    """
    from .performance import audit_mode
    profile = audit_mode(mode)
    if not isinstance(source, str):
        raise TypeError("source must be text")
    source_bytes = len(source.encode("utf-8"))
    if source_bytes > max_source_bytes:
        return {"schema": "pegrex.security-analysis.v1", "findings": [],
                "unknowns": [f"source input budget exceeded: {source_bytes} > {max_source_bytes} bytes"],
                "coverage": {"status": "unknown", "language": "python", "mode": mode,
                             "limits": ["source byte limit exceeded"]},
                "security_model": MODEL_VERSION, "resource_usage": {"source_bytes": source_bytes}}
    started = time.monotonic()
    max_iterations = 1_000 if mode == "fast" else 50_000
    max_ast_nodes = 20_000 if mode == "fast" else 250_000
    try:
        result = analyze_modules({module: (path, source)}, source_rules=DEFAULT_SOURCES + FRAMEWORK_SOURCES,
                                 sink_rules=DEFAULT_SINKS + FRAMEWORK_SINKS,
                                 max_iterations=max_iterations, max_seconds=profile.max_seconds,
                                 max_ast_nodes=max_ast_nodes, report_parameters=False)
        elapsed = time.monotonic() - started
        remaining = max(0.001, profile.max_seconds - elapsed)
        # Secret analysis shares the overall deadline instead of receiving a new
        # full budget. Its result is merged as a distinct source/sink policy.
        secret_result = analyze_secrets(source, path=path, max_seconds=remaining,
                                        max_iterations=max_iterations, max_ast_nodes=max_ast_nodes)
    except (SyntaxError, ValueError, TimeoutError, UnicodeError, MemoryError) as exc:
        return {"schema": "pegrex.security-analysis.v1", "findings": [],
                "unknowns": [f"analysis unavailable: {type(exc).__name__}"],
                "coverage": {"status": "unknown", "language": "python", "mode": mode,
                             "limits": ["parse failure or resource limit prevented a complete analysis"]},
                "security_model": MODEL_VERSION,
                "resource_usage": {"source_bytes": source_bytes,
                                   "elapsed_seconds": round(time.monotonic() - started, 6)}}
    findings = result.get("findings", []) + secret_result.get("findings", [])
    deduplicated = {}
    for finding in findings:
        identity = json.dumps(finding, sort_keys=True, separators=(",", ":"), default=str)
        deduplicated[identity] = finding
    result["analysis_schema"] = result.get("schema")
    result["schema"] = "pegrex.security-analysis.v1"
    result["findings"] = [deduplicated[key] for key in sorted(deduplicated)]
    result["unknowns"] = sorted(set(result.get("unknowns", [])) | set(secret_result.get("unknowns", [])))
    result["security_model"] = MODEL_VERSION
    result["coverage"] = {"status": "partial",
                           "language": "python", "mode": mode, "model_version": MODEL_VERSION,
                           "limits": ["dynamic dispatch, reflection, aliases and implicit flows are not resolved completely",
                                      "framework model signatures are conservative and incomplete",
                                      "secret-flow rules are static source/sink models and do not prove absence of exfiltration",
                                      "sanitization is sink-context-specific; a sanitizer name is not a general safety proof"]}
    result["resource_usage"] = {"source_bytes": source_bytes,
                                "elapsed_seconds": round(time.monotonic() - started, 6),
                                "max_seconds": profile.max_seconds,
                                "max_iterations_per_function": max_iterations,
                                "max_ast_nodes_per_file": max_ast_nodes}
    return result


def analyze_iac_source(source: str, *, path="<memory>.tf") -> dict:
    findings = audit_terraform(source)
    return {"schema": "pegrex.iac-audit.v1", "file": path, "findings": findings,
            "coverage": "terraform-subset", "unknowns": ["only explicitly modeled Terraform patterns were checked"]}


def analyze_iac_policy(document, *, path="<memory>.json") -> dict:
    try:
        parsed = json.loads(document) if isinstance(document, str) else document
        findings = audit_policy(parsed)
        return {"schema": "pegrex.iac-audit.v1", "file": path, "findings": findings, "coverage": "iam-json-subset", "unknowns": []}
    except (ValueError, TypeError, AttributeError) as exc:
        return {"schema": "pegrex.iac-audit.v1", "file": path, "findings": [], "coverage": "unknown", "unknowns": [f"invalid or unsupported policy: {type(exc).__name__}"]}


def correlate_iac_assumptions(application_assumptions, iac_findings) -> dict:
    """Flag explicit mismatches between declared app assumptions and IaC findings.

    Assumptions use a narrow vocabulary: ``requires_private_storage`` and
    ``requires_restricted_egress``. This is correlation, not cloud-provider proof.
    """
    assumptions = set(application_assumptions or ())
    kinds = {row.get("kind") for row in (iac_findings or []) if isinstance(row, dict)}
    conflicts = []
    if "requires_private_storage" in assumptions and ({"s3-public-read", "s3-public-access-block-disabled", "wildcard-admin"} & kinds):
        conflicts.append({"kind": "application-iac-assumption-conflict", "assumption": "requires_private_storage", "evidence": sorted({"s3-public-read", "s3-public-access-block-disabled", "wildcard-admin"} & kinds)})
    if "requires_restricted_egress" in assumptions and "unrestricted-egress" in kinds:
        conflicts.append({"kind": "application-iac-assumption-conflict", "assumption": "requires_restricted_egress", "evidence": ["unrestricted-egress"]})
    if "requires_private_network" in assumptions and ({"public-database", "public-admin-ingress"} & kinds):
        conflicts.append({"kind": "application-iac-assumption-conflict", "assumption": "requires_private_network", "evidence": sorted({"public-database", "public-admin-ingress"} & kinds)})
    if "requires_encrypted_storage" in assumptions and "unencrypted-database" in kinds:
        conflicts.append({"kind": "application-iac-assumption-conflict", "assumption": "requires_encrypted_storage", "evidence": ["unencrypted-database"]})
    return {"schema": "pegrex.iac-app-correlation.v1", "conflicts": conflicts,
            "coverage": "explicit-assumption-subset", "unknowns": ["application assumptions and IaC semantics are incomplete"]}
