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
        source_identities = {
            f"{side}_source_sha256": provenance[side]["sha256"]
            for side in ("before", "after") if provenance[side].get("sha256")
        }
        certificate = certificate_document(verdict, claim, evidence={
            "distinguishing": result.get("distinguishing", [])},
            counterexample=result.get("counterexample"),
            unknowns=[] if verdict == "proved" else ([result["note"]] if result.get("note") else []),
            **source_identities)
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


def patch_review(before_path: str, after_path: str, *, claim="equivalent") -> dict:
    """Evidence-first patch review; never upgrades unknown to success."""
    verification = verify_change(before_path, after_path, claim=claim)
    certificate = verification.get("data", {}).get("certificate")
    unresolved = list(verification.get("unknowns", []))
    verified_properties = []
    if certificate and certificate.get("verdict") == "proved":
        verified_properties.append({"claim": claim, "certificate": certificate})
    counterexample = None
    if certificate and certificate.get("verdict") == "refuted":
        counterexample = certificate.get("counterexample")
    if not verified_properties and counterexample is None and not unresolved:
        unresolved.append(unknown_document("no-independent-proof-or-counterexample"))
    return {"schema": "pegrex.patch-review.v1", "verdict": verification["verdict"],
            "verified_properties": verified_properties, "counterexample": counterexample,
            "unresolved_obligations": unresolved, "provenance": verification.get("provenance", {})}


def repair_candidates(candidate_generator, isolated_test_runner, independent_verifier, *, max_candidates=3) -> dict:
    """Evaluate generated candidates through caller-supplied isolation and verifier adapters.

    The test runner must provide an actual isolation boundary. This function
    deliberately does not execute candidate code itself.
    """
    if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or not 1 <= max_candidates <= 20:
        raise ValueError("max_candidates must be between 1 and 20")
    candidates, results = candidate_generator(max_candidates), []
    if not isinstance(candidates, (list, tuple)):
        return {"schema": "pegrex.repair-loop.v1", "status": "unknown", "results": [],
                "unknowns": ["candidate generator must return a list or tuple"]}
    for index, candidate in enumerate(candidates[:max_candidates]):
        row = {"candidate": index, "test": None, "verification": None, "status": "unknown"}
        if not isinstance(candidate, dict) or not isinstance(candidate.get("source"), str):
            row["reason"] = "candidate must be an object with source text"; results.append(row); continue
        try:
            test = isolated_test_runner(candidate["source"])
            row["test"] = test
            if not isinstance(test, dict) or test.get("status") != "passed":
                row["reason"] = "isolated tests did not pass"; results.append(row); continue
            proof = independent_verifier(candidate["source"])
            row["verification"] = proof
            if isinstance(proof, dict) and proof.get("verdict") == "proved": row["status"] = "promising"
            else: row["reason"] = "independent verification did not prove required property"
        except Exception as exc:
            row["reason"] = "adapter failure: " + type(exc).__name__
        results.append(row)
    promising = [row for row in results if row["status"] == "promising"]
    return {"schema": "pegrex.repair-loop.v1", "status": "candidate-ready-for-review" if promising else "unknown",
            "results": results, "promising_candidates": [row["candidate"] for row in promising],
            "unknowns": [] if promising else ["no candidate passed isolated tests and independent verification"]}
