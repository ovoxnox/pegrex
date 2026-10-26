"""Typed, evidence-bearing tools for agents; no prose-only answer channel."""
from __future__ import annotations

import hashlib
from pathlib import Path

from .core import get_engine
from .schema import certificate_document, contract_document, unknown_document

SCHEMA = "pegrex.agent-evidence.v1"


def _file_identity(path) -> dict:
    path = Path(path)
    try:
        data = path.read_bytes()
        return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data)}
    except OSError as error:
        return {"path": str(path), "error": str(error)}


def _envelope(tool, data, *, verdict=None, unknowns=(), provenance=None) -> dict:
    return {"schema": SCHEMA, "tool": tool, "verdict": verdict or (
        "unknown" if unknowns else "ok"), "data": data,
        "unknowns": list(unknowns), "provenance": provenance or {}}


def query_contracts(path: str, *, language: str | None = None,
                    function: str | None = None) -> dict:
    """Implement query contracts with the module's explicit API and failure semantics."""
    provenance = _file_identity(path)
    try:
        if function is None:
            result = get_engine().contracts_file(path, language)
        else:
            from .core import SourceDocument
            document = SourceDocument.from_path(path, language)
            result = get_engine().extract_contracts(document.text, document.language,
                                                    path=str(path), entrypoint=function)
        rows = []
        for row in result.data or []:
            if function is not None and row.get("function") != function:
                continue
            document = row if row.get("schema") == "pegrex.contract.v1" else contract_document(
                constraints=row.get("constraints", ()), outcome=row.get("outcome"),
                function=row.get("function"), source_hash=row.get("source_hash"),
                metadata=row.get("metadata", {}))
            rows.append(document)
        unknowns = [unknown_document("contract-extraction", source=str(path), details={"reason": row})
                    for row in result.unknowns]
        verdict = "unknown" if unknowns or result.status.value == "error" else "ok"
        return _envelope("contracts.query", {"contracts": rows, "count": len(rows)},
                         verdict=verdict, unknowns=unknowns, provenance=provenance)
    except Exception as error:
        return _envelope("contracts.query", {"contracts": [], "count": 0}, verdict="unknown",
                         unknowns=[unknown_document("contract-query-failed", source=str(path),
                                                    details={"reason": str(error)})],
                         provenance=provenance)


def verify_change(before_path: str, after_path: str, *, claim="equivalent") -> dict:
    """Implement verify change with the module's explicit API and failure semantics."""
    from .semantics import verify_patch
    provenance = {"before": _file_identity(before_path), "after": _file_identity(after_path)}
    try:
        result = verify_patch(before_path, after_path, claim)
        if result.get("verified") is True:
            verdict = "proved"
        elif result.get("counterexample", {}).get("confirmed") is True:
            verdict = "refuted"
        else:
            verdict = "unknown"
        certificate = certificate_document(verdict, claim, evidence={
            "distinguishing": result.get("distinguishing", [])},
            counterexample=result.get("counterexample"),
            unknowns=[] if verdict == "proved" else ([result["note"]] if result.get("note") else []),
            before=provenance["before"], after=provenance["after"])
        return _envelope("verifier.check", {"certificate": certificate,
                                            "verification": result},
                         verdict=verdict, unknowns=certificate["unknowns"], provenance=provenance)
    except Exception as error:
        unknown = unknown_document("verifier-failed", details={"reason": str(error)})
        return _envelope("verifier.check", {"certificate": None, "verification": None},
                         verdict="unknown", unknowns=[unknown], provenance=provenance)


def find_counterexample(before_path: str, after_path: str) -> dict:
    """Implement find counterexample with the module's explicit API and failure semantics."""
    evidence = verify_change(before_path, after_path)
    verification = (evidence["data"].get("verification") or {})
    counterexample = verification.get("counterexample")
    confirmed = bool(counterexample and counterexample.get("confirmed") is True)
    return _envelope("counterexample.search", {
        "counterexample": counterexample if confirmed else None,
        "confirmed": confirmed, "certificate": evidence["data"].get("certificate")},
        verdict="refuted" if confirmed else evidence["verdict"],
        unknowns=evidence["unknowns"], provenance=evidence["provenance"])


def agent_tool_manifest() -> dict:
    """Implement agent tool manifest with the module's explicit API and failure semantics."""
    return {"schema": "pegrex.agent-tools.v1", "tools": [
        {"name": "contracts.query", "input": ["path", "language?", "function?"],
         "output": "pegrex.contract.v1[]", "evidence": SCHEMA},
        {"name": "counterexample.search", "input": ["before_path", "after_path"],
         "output": "confirmed counterexample|null", "evidence": SCHEMA},
        {"name": "verifier.check", "input": ["before_path", "after_path", "claim?"],
         "output": "pegrex.certificate.v1", "evidence": SCHEMA},
    ]}
