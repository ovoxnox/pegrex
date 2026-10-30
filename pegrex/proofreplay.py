"""Standalone, solver-free replay for canonical equality certificates.

This file intentionally uses only the Python standard library. It can be run
directly, outside the original analysis process: ``python proofreplay.py C.json``.
"""
from __future__ import annotations
import hashlib, json, re, sys
from pathlib import Path
try:  # Support both ``python -m pegrex.proofreplay`` and direct script replay.
    from pegrex.finiteproof import check_finite_domain_proof
except ModuleNotFoundError:  # pragma: no cover - exercised by direct script launch
    from finiteproof import check_finite_domain_proof
SCHEMA = "pegrex.proof-replay.v1"
_MAX_CONTRACTS, _MAX_CONSTRAINTS, _MAX_TEXT = 10_000, 1_000, 10_000
_MAX_CERTIFICATE_BYTES = 5_000_000
_HASH = re.compile(r"^[0-9a-f]{64}$")
_TOP_LEVEL_FIELDS = {"schema", "schema_version", "verdict", "claim", "unknowns", "before_source_sha256", "after_source_sha256", "evidence"}


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
    if len({_json(row) for row in result}) != len(result): raise ValueError("duplicate canonical contract")
    return sorted(result, key=_json)


def replay_certificate(certificate, *, before_source=None, after_source=None) -> dict:
    """Implement replay certificate with the module's explicit API and failure semantics."""
    try:
        if not isinstance(certificate, dict) or certificate.get("schema") != "pegrex.certificate.v1": return _unknown("unsupported-certificate")
        if type(certificate.get("schema_version")) is not int or certificate["schema_version"] != 1: return _unknown("unsupported-certificate-version")
        if set(certificate) - _TOP_LEVEL_FIELDS: return _unknown("unsupported-certificate-fields")
        if not isinstance(certificate.get("unknowns"), list) or any(not isinstance(x, str) for x in certificate["unknowns"]): return _unknown("malformed-unknowns")
        for key in ("before_source_sha256", "after_source_sha256"):
            if certificate.get(key) is not None and (not isinstance(certificate[key], str) or not _HASH.fullmatch(certificate[key])): return _unknown("malformed-source-hash")
        claim = certificate.get("claim")
        if claim == "finite-domain-equivalent":
            if certificate.get("verdict") not in {"proved", "refuted"} or certificate.get("unknowns"):
                return _unknown("not-a-complete-proof")
            evidence = certificate.get("evidence")
            if not isinstance(evidence, dict) or set(evidence) != {"finite_domain_proof"}:
                return _unknown("semantic-evidence-missing-or-unsupported-fields")
            source_checks = 0
            for supplied, key in ((before_source, "before_source_sha256"), (after_source, "after_source_sha256")):
                if certificate.get(key) is not None and supplied is None:
                    return _unknown("source-replay-input-required")
                if supplied is not None:
                    raw = supplied.encode("utf-8") if isinstance(supplied, str) else bytes(supplied)
                    if certificate.get(key) != hashlib.sha256(raw).hexdigest():
                        return _unknown(key + "-mismatch")
                    source_checks += 1
            result = check_finite_domain_proof(evidence.get("finite_domain_proof"))
            if result.get("verdict") not in {"proved", "refuted"} or not result.get("checked"):
                return _unknown("finite-domain-proof-not-established")
            if result["verdict"] != certificate["verdict"]:
                return _unknown("finite-domain-verdict-mismatch")
            return {"schema": SCHEMA, "schema_version": 1, "replayed": True,
                    "verdict": result["verdict"], "claim": claim,
                    "proof_result": result, "solver_used": False,
                    "source_hashes_checked": source_checks,
                    "checker": "pegrex-finite-domain-enumerator-v1"}
        if certificate.get("verdict") != "proved" or certificate.get("unknowns"): return _unknown("not-a-complete-proof")
        if claim not in {"contract-set-identical", "equivalent", "patch-equivalent"}:
            return _unknown("unsupported-claim")
        if claim in {"equivalent", "patch-equivalent"}:
            return _unknown("semantic-equivalence-requires-an-independent-proof-checker")
        evidence = certificate.get("evidence", {})
        allowed_evidence = {"before_contracts", "after_contracts", "before_contracts_sha256", "after_contracts_sha256"}
        if not isinstance(evidence, dict) or set(evidence) - allowed_evidence: return _unknown("unsupported-evidence-fields")
        if not {"before_contracts", "after_contracts"} <= set(evidence): return _unknown("contract-evidence-missing")
        before, after = _contracts(evidence.get("before_contracts")), _contracts(evidence.get("after_contracts"))
        if before != after: return _unknown("contract-sets-differ")
        for field, expected in (("before_contracts_sha256", _digest(before)), ("after_contracts_sha256", _digest(after))):
            supplied = evidence.get(field)
            if supplied is not None and (not isinstance(supplied, str) or not _HASH.fullmatch(supplied) or supplied != expected): return _unknown(field.replace("_", "-") + "-mismatch")
        source_checks = 0
        for supplied, key in ((before_source, "before_source_sha256"), (after_source, "after_source_sha256")):
            if certificate.get(key) is not None and supplied is None: return _unknown("source-replay-input-required")
            if supplied is not None:
                raw = supplied.encode("utf-8") if isinstance(supplied, str) else bytes(supplied)
                if certificate.get(key) != hashlib.sha256(raw).hexdigest(): return _unknown(key + "-mismatch")
                source_checks += 1
        return {"schema": SCHEMA, "schema_version": 1, "replayed": True, "verdict": "proved",
                "claim": "contract-set-identical",
                "certificate_sha256": hashlib.sha256(_json(certificate).encode()).hexdigest(),
                "contract_set_sha256": _digest(before), "solver_used": False,
                "source_hashes_checked": source_checks,
                "checker": "standalone-canonical-json-sha256-v1"}
    except (ValueError, TypeError, RecursionError, AttributeError) as error:
        return _unknown("malformed-certificate: " + str(error)[:200])


def main(argv=None):
    """Implement main with the module's explicit API and failure semantics."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) not in {1, 5}:
        print(json.dumps(_unknown("usage: proofreplay.py certificate.json [--before-source PATH --after-source PATH]")))
        return 2
    try:
        cert_path = argv[0]
        options = argv[1:]
        if options and (options[0] != "--before-source" or options[2] != "--after-source"):
            print(json.dumps(_unknown("invalid-source-replay-arguments"))); return 2
        before_path = options[1] if options else None
        after_path = options[3] if options else None
        path = Path(cert_path)
        with path.open("rb") as stream:
            raw = stream.read(_MAX_CERTIFICATE_BYTES + 1)
        if len(raw) > _MAX_CERTIFICATE_BYTES:
            print(json.dumps(_unknown("certificate-size-limit-exceeded")))
            return 2

        def unique_object(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate JSON object key")
                result[key] = value
            return result

        certificate = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (OSError, ValueError, UnicodeDecodeError, RecursionError) as error:
        print(json.dumps(_unknown("certificate-read: " + str(error)[:200])))
        return 2
    try:
        before_source = Path(before_path).read_bytes() if before_path else None
        after_source = Path(after_path).read_bytes() if after_path else None
    except OSError:
        print(json.dumps(_unknown("source-replay-input-read-failed"), sort_keys=True)); return 2
    result = replay_certificate(certificate, before_source=before_source, after_source=after_source)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["replayed"] else 1

if __name__ == "__main__": raise SystemExit(main())
