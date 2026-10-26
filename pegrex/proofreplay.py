"""Standalone, solver-free replay for canonical equality certificates.

This file intentionally uses only the Python standard library. It can be run
directly, outside the original analysis process: ``python proofreplay.py C.json``.
"""
from __future__ import annotations
import hashlib, json, sys
SCHEMA = "pegrex.proof-replay.v1"
_MAX_CONTRACTS, _MAX_CONSTRAINTS, _MAX_TEXT = 10_000, 1_000, 10_000


def _json(value): return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
def _digest(value): return hashlib.sha256(_json(value).encode()).hexdigest()
def _unknown(reason): return {"schema": SCHEMA, "schema_version": 1, "replayed": False,
                              "verdict": "unknown", "reason": reason, "solver_used": False}
def _contracts(rows):
    if not isinstance(rows, list) or len(rows) > _MAX_CONTRACTS: raise ValueError("contract bound")
    result = []
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"constraints", "outcome"}: raise ValueError("contract shape")
        constraints, outcome = row["constraints"], row["outcome"]
        if not isinstance(constraints, list) or len(constraints) > _MAX_CONSTRAINTS: raise ValueError("constraint bound")
        if not isinstance(outcome, str) or len(outcome) > _MAX_TEXT: raise ValueError("outcome shape")
        if any(not isinstance(x, str) or len(x) > _MAX_TEXT for x in constraints): raise ValueError("constraint shape")
        result.append({"constraints": sorted(constraints), "outcome": outcome})
    return sorted(result, key=_json)


def replay_certificate(certificate, *, before_source=None, after_source=None) -> dict:
    """Implement replay certificate with the module's explicit API and failure semantics."""
    try:
        if not isinstance(certificate, dict) or certificate.get("schema") != "pegrex.certificate.v1"                 or certificate.get("schema_version") != 1: return _unknown("unsupported-certificate")
        if certificate.get("verdict") != "proved" or certificate.get("unknowns"): return _unknown("not-a-complete-proof")
        if certificate.get("claim") not in {"equivalent", "patch-equivalent"}: return _unknown("unsupported-claim")
        evidence = certificate.get("evidence", {})
        before, after = _contracts(evidence.get("before_contracts")), _contracts(evidence.get("after_contracts"))
        if before != after: return _unknown("contract-sets-differ")
        if evidence.get("before_contracts_sha256") not in {None, _digest(before)}: return _unknown("before-contract-hash")
        if evidence.get("after_contracts_sha256") not in {None, _digest(after)}: return _unknown("after-contract-hash")
        for supplied, key in ((before_source, "before_source_sha256"), (after_source, "after_source_sha256")):
            if supplied is not None:
                raw = supplied.encode() if isinstance(supplied, str) else bytes(supplied)
                if certificate.get(key) != hashlib.sha256(raw).hexdigest(): return _unknown(key + "-mismatch")
        return {"schema": SCHEMA, "schema_version": 1, "replayed": True, "verdict": "proved",
                "certificate_sha256": hashlib.sha256(_json(certificate).encode()).hexdigest(),
                "contract_set_sha256": _digest(before), "solver_used": False,
                "checker": "standalone-canonical-json-sha256-v1"}
    except (ValueError, TypeError, RecursionError, AttributeError) as error:
        return _unknown("malformed-certificate: " + str(error)[:200])


def main(argv=None):
    """Implement main with the module's explicit API and failure semantics."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) != 1:
        print(json.dumps(_unknown("usage: proofreplay.py certificate.json")))
        return 2
    try:
        with open(argv[0], "rb") as stream: certificate = json.load(stream)
    except (OSError, ValueError) as error:
        print(json.dumps(_unknown("certificate-read: " + str(error))))
        return 2
    result = replay_certificate(certificate)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["replayed"] else 1

if __name__ == "__main__": raise SystemExit(main())
