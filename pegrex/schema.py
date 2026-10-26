"""Stable, versioned machine-readable documents and compatibility envelopes.

Version 1 is additive: existing report keys remain in place, while typed
findings, contracts, UNKNOWNs, and certificates gain explicit schema identity.
"""
from __future__ import annotations

import copy
import json
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
}


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


def schema_catalog() -> dict:
    """Return independent JSON Schema documents, safe to serialize or modify."""
    return copy.deepcopy(SCHEMA_DEFINITIONS)


def validate_document(document: dict) -> list[str]:
    """Implement validate document with the module's explicit API and failure semantics."""
    if not isinstance(document, dict):
        return ["document must be a JSON object"]
    schema = document.get("schema")
    definition = SCHEMA_DEFINITIONS.get(schema)
    if definition is None:
        return [f"unsupported or missing schema {schema!r}"]
    errors = []
    for key in definition["required"]:
        if key not in document:
            errors.append(f"missing required property {key!r}")
    for key, rule in definition["properties"].items():
        if key not in document:
            continue
        value = document[key]
        if "const" in rule and value != rule["const"]:
            errors.append(f"{key}: expected {rule['const']!r}")
        if "enum" in rule and value not in rule["enum"]:
            errors.append(f"{key}: expected one of {rule['enum']!r}")
        expected = rule.get("type")
        types = expected if isinstance(expected, list) else [expected]
        checks = {"string": str, "object": dict, "array": list,
                  "boolean": bool, "null": type(None)}
        valid = True
        if expected == "integer":
            valid = isinstance(value, int) and not isinstance(value, bool)
        elif expected:
            valid = any(isinstance(value, checks[name]) for name in types if name in checks)
            if "boolean" not in types and isinstance(value, bool) and "integer" in types:
                valid = False
        if not valid:
            errors.append(f"{key}: expected JSON type {expected}")
        if rule.get("minimum") is not None and isinstance(value, (int, float)) and value < rule["minimum"]:
            errors.append(f"{key}: below minimum {rule['minimum']}")
        if rule.get("minLength") is not None and isinstance(value, str) and len(value) < rule["minLength"]:
            errors.append(f"{key}: shorter than {rule['minLength']}")
    if schema == CERTIFICATE and not errors:
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
