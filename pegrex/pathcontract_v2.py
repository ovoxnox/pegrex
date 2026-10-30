"""Strict validator for the portable PathContract v2 interchange format.

Validation checks shape and vocabulary only. A valid record is not a proof of
sound extraction, source equivalence, termination, or effect completeness.
"""
from __future__ import annotations

import re
from typing import Any

SCHEMA = "pegrex.path-contract.v2"
SCHEMA_VERSION = 2
_HASH = re.compile(r"^[0-9a-f]{64}$")
_OUTCOMES = {"return", "raise", "terminate", "diverge", "unknown"}
_EFFECTS = {
    "state-write", "io", "filesystem", "network", "process",
    "nondeterministic", "synchronization", "allocation", "unknown",
}
_TERMINATION = {"proven", "refuted", "unknown", "not-claimed"}
_INTEGER = {"unbounded", "fixed-width-signed", "fixed-width-unsigned", "unknown"}
_OVERFLOW = {"wrap", "trap", "undefined", "not-applicable", "unknown"}
_FLOAT = {"ieee754", "decimal", "not-applicable", "unknown"}
_TOP_KEYS = {
    "schema", "schema_version", "source", "function", "guards", "outcome",
    "effects", "nondeterministic", "termination", "numeric_semantics", "unknowns",
}


def validate_path_contract_v2(record: Any) -> dict:
    """Validate v2 structure and return errors plus a non-proof completeness label."""
    errors: list[str] = []

    def err(path: str, message: str) -> None:
        errors.append(f"{path}: {message}")

    if not isinstance(record, dict):
        return {"schema": "pegrex.path-contract-validation.v1", "valid": False,
                "completeness": "unknown", "errors": ["$: expected object"]}
    extras = set(record) - _TOP_KEYS
    if extras:
        err("$", f"unsupported fields: {', '.join(sorted(map(str, extras)))}")
    if record.get("schema") != SCHEMA:
        err("schema", f"must equal {SCHEMA!r}")
    if record.get("schema_version") != SCHEMA_VERSION or isinstance(record.get("schema_version"), bool):
        err("schema_version", "must equal integer 2")

    source = record.get("source")
    if not isinstance(source, dict):
        err("source", "must be an object")
    else:
        if set(source) - {"path", "sha256", "span"}:
            err("source", "contains unsupported fields")
        if "path" in source and source["path"] is not None and not isinstance(source["path"], str):
            err("source.path", "must be a string or null")
        if not isinstance(source.get("sha256"), str) or not _HASH.fullmatch(source["sha256"]):
            err("source.sha256", "must be a lowercase SHA-256 hex digest")
        span = source.get("span")
        if not isinstance(span, dict):
            err("source.span", "must be an object")
        else:
            if set(span) != {"start", "end", "unit", "convention"}:
                err("source.span", "requires start, end, unit, and convention only")
            start, end = span.get("start"), span.get("end")
            if not isinstance(start, int) or isinstance(start, bool) or start < 0:
                err("source.span.start", "must be a non-negative integer")
            if not isinstance(end, int) or isinstance(end, bool) or end < 0:
                err("source.span.end", "must be a non-negative integer")
            if isinstance(start, int) and not isinstance(start, bool) and isinstance(end, int) and not isinstance(end, bool) and end < start:
                err("source.span", "end must be greater than or equal to start")
            if span.get("unit") != "unicode-codepoint":
                err("source.span.unit", "must be unicode-codepoint")
            if span.get("convention") != "zero-based-half-open":
                err("source.span.convention", "must be zero-based-half-open")

    if "function" in record and record["function"] is not None and not isinstance(record["function"], str):
        err("function", "must be a string or null")

    guards = record.get("guards")
    if not isinstance(guards, list) or any(not isinstance(x, str) for x in guards):
        err("guards", "must be an array of strings")

    outcome = record.get("outcome")
    if not isinstance(outcome, dict):
        err("outcome", "must be an object")
    else:
        if set(outcome) - {"kind", "expression", "exception_type"}:
            err("outcome", "contains unsupported fields")
        if outcome.get("kind") not in _OUTCOMES:
            err("outcome.kind", f"must be one of {sorted(_OUTCOMES)}")
        if "expression" in outcome and not isinstance(outcome["expression"], str):
            err("outcome.expression", "must be a string")
        if "exception_type" in outcome and not isinstance(outcome["exception_type"], str):
            err("outcome.exception_type", "must be a string")
        if outcome.get("kind") == "raise" and not outcome.get("exception_type"):
            err("outcome.exception_type", "required when kind is raise")

    effects = record.get("effects")
    if not isinstance(effects, list) or any(not isinstance(x, str) or x not in _EFFECTS for x in effects):
        err("effects", f"must be an array drawn from {sorted(_EFFECTS)}")
    elif len(set(effects)) != len(effects):
        err("effects", "duplicate effects are not allowed")

    if not isinstance(record.get("nondeterministic"), bool):
        err("nondeterministic", "must be a boolean")

    termination = record.get("termination")
    if not isinstance(termination, dict):
        err("termination", "must be an object")
    else:
        if set(termination) - {"status", "method"}:
            err("termination", "contains unsupported fields")
        if termination.get("status") not in _TERMINATION:
            err("termination.status", f"must be one of {sorted(_TERMINATION)}")
        if "method" in termination and not isinstance(termination["method"], str):
            err("termination.method", "must be a string")

    numeric = record.get("numeric_semantics")
    if not isinstance(numeric, dict):
        err("numeric_semantics", "must be an object")
    else:
        if set(numeric) != {"integer", "overflow", "floating_point"}:
            err("numeric_semantics", "requires integer, overflow, and floating_point only")
        if numeric.get("integer") not in _INTEGER:
            err("numeric_semantics.integer", f"must be one of {sorted(_INTEGER)}")
        if numeric.get("overflow") not in _OVERFLOW:
            err("numeric_semantics.overflow", f"must be one of {sorted(_OVERFLOW)}")
        if numeric.get("floating_point") not in _FLOAT:
            err("numeric_semantics.floating_point", f"must be one of {sorted(_FLOAT)}")

    unknowns = record.get("unknowns")
    if not isinstance(unknowns, list) or any(not isinstance(x, str) or not x.strip() for x in unknowns):
        err("unknowns", "must be an array of non-empty strings")

    is_valid = not errors
    incomplete = (not is_valid or bool(unknowns) or
                  (isinstance(outcome, dict) and outcome.get("kind") == "unknown") or
                  (isinstance(termination, dict) and termination.get("status") == "unknown") or
                  (isinstance(effects, list) and "unknown" in effects) or
                  (isinstance(numeric, dict) and any(v == "unknown" for v in numeric.values())))
    return {"schema": "pegrex.path-contract-validation.v1", "valid": is_valid,
            "completeness": "unknown" if incomplete else "described",
            "is_proof": False, "errors": errors}
