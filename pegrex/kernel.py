"""Minimal trusted certificate kernel.

The kernel trusts canonical JSON/SHA-256, structural contract equality, and a
small bounded finite-domain expression evaluator. It deliberately imports no
parser, solver, or source analyzer. Unsupported certificate forms fail closed
as UNKNOWN, never as proofs.
"""
from __future__ import annotations

from .finiteproof import check_finite_domain_proof

import hashlib
import json

SCHEMA = "pegrex.certificate.v1"
RESULT_SCHEMA = "pegrex.kernel-check.v1"
_MAX_CONTRACTS = 10_000
_MAX_CONSTRAINTS = 1_000
_MAX_TEXT = 10_000


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _unknown(reason, **details):
    return {"schema": RESULT_SCHEMA, "checked": False, "verdict": "unknown",
            "reason": reason, "details": details}


def _contracts(value, side):
    if not isinstance(value, list) or len(value) > _MAX_CONTRACTS:
        raise ValueError(f"{side}: invalid contract list or resource bound")
    normalized = []
    for row in value:
        if not isinstance(row, dict) or set(row) - {"constraints", "outcome"}:
            raise ValueError(f"{side}: contract has unsupported fields")
        constraints = row.get("constraints")
        outcome = row.get("outcome")
        if (not isinstance(constraints, list) or len(constraints) > _MAX_CONSTRAINTS
                or not isinstance(outcome, str) or len(outcome) > _MAX_TEXT
                or any(not isinstance(item, str) or len(item) > _MAX_TEXT
                       for item in constraints)):
            raise ValueError(f"{side}: malformed or oversized contract")
        normalized.append({"constraints": sorted(constraints), "outcome": outcome})
    return sorted(normalized, key=_canonical)


def contract_set_identity(contracts) -> str:
    """Public only for certificate producers; the checker recomputes it."""
    return hashlib.sha256(_canonical(contracts)).hexdigest()


def check_certificate(certificate) -> dict:
    """Independently accept only a well-formed canonical equality proof."""
    try:
        if not isinstance(certificate, dict) or certificate.get("schema") != SCHEMA:
            return _unknown("unsupported-certificate-schema")
        if certificate.get("schema_version") != 1:
            return _unknown("unsupported-certificate-version")
        verdict = certificate.get("verdict")
        if verdict not in {"proved", "refuted", "unknown"}:
            return _unknown("invalid-verdict")
        claim = certificate.get("claim")
        if claim not in {"contract-set-identical", "equivalent", "patch-equivalent",
                         "finite-domain-equivalent"}:
            return _unknown("unsupported-claim", claim=claim)
        if claim == "finite-domain-equivalent":
            if certificate.get("unknowns") or verdict not in {"proved", "refuted"}:
                return _unknown("finite-domain-certificate-not-complete")
            evidence = certificate.get("evidence")
            if not isinstance(evidence, dict):
                return _unknown("finite-domain-evidence-missing")
            result = check_finite_domain_proof(evidence.get("finite_domain_proof"))
            if (result.get("checked") and result.get("verdict") in {"proved", "refuted"}
                    and result["verdict"] == verdict):
                return {"schema": RESULT_SCHEMA, "checked": True,
                        "verdict": verdict, "claim": claim,
                        "proof": result, "kernel": "finite-domain-enumerator-v1"}
            return _unknown("finite-domain-proof-not-established-or-verdict-mismatch",
                            proof_result=result)
        # Canonical contract equality proves only that two supplied contract
        # sets are structurally identical. It does not establish that the
        # source programs are behaviorally equivalent or that extraction was
        # complete. General source equivalence remains unsupported.
        if claim in {"equivalent", "patch-equivalent"}:
            return _unknown(
                "semantic-equivalence-requires-an-independent-proof-checker",
                claim=claim)
        if certificate.get("unknowns") and verdict == "proved":
            return _unknown("proved-certificate-contains-unknowns")
        evidence = certificate.get("evidence")
        if not isinstance(evidence, dict):
            return _unknown("evidence-missing")
        before = _contracts(evidence.get("before_contracts"), "before")
        after = _contracts(evidence.get("after_contracts"), "after")
        before_digest = contract_set_identity(before)
        after_digest = contract_set_identity(after)
        if evidence.get("before_contracts_sha256") not in {None, before_digest} or \
                evidence.get("after_contracts_sha256") not in {None, after_digest}:
            return _unknown("contract-identity-mismatch")
        if verdict == "unknown":
            return _unknown("certificate-is-explicitly-unknown",
                            before_contracts_sha256=before_digest,
                            after_contracts_sha256=after_digest)
        if verdict == "refuted":
            return _unknown("counterexample-execution-is-outside-minimal-kernel")
        if before != after:
            return _unknown("forged-equivalence-proof", before_contracts_sha256=before_digest,
                            after_contracts_sha256=after_digest)
        return {"schema": RESULT_SCHEMA, "checked": True, "verdict": "proved",
                "claim": "contract-set-identical",
                "before_contracts_sha256": before_digest,
                "after_contracts_sha256": after_digest,
                "kernel": "canonical-contract-equality-v1"}
    except (ValueError, TypeError, RecursionError) as error:
        return _unknown("malformed-certificate", reason=str(error)[:300])
