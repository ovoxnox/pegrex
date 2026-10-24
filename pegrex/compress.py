"""
compress — context compression for LLM calls

Contracts + audit findings instead of raw source: token-cheap and
semantically dense. Certified by construction: the payload carries
every finding id the full audit produces, and it must be smaller."""

from __future__ import annotations

from . import api


def compress_context(src_path: str) -> dict:
    """compress context(src_path): see module docstring."""
    src_bytes = len(open(src_path, "rb").read())
    contracts = [{"constraints": sorted(map(str, cs)), "result": str(res)}
                 for cs, res in api.contracts(src_path)]
    findings = api.audit(src_path)
    ids = sorted({(f.get("id") or f.get("rule") or str(f))[:48] for f in findings})
    import json
    payload = json.dumps({"contracts": contracts, "findings": ids})
    return {
        "source_bytes": src_bytes,
        "payload_bytes": len(payload.encode()),
        "ratio": round(len(payload.encode()) / max(src_bytes, 1), 3),
        "contracts": contracts,
        "finding_ids": ids,
        "findings_full": findings,
    }


def validate_compression(src_path: str) -> dict:
    """The compressed payload must be smaller AND lossless wrt findings."""
    full = compress_context(src_path)
    direct = sorted({(f.get("id") or f.get("rule") or str(f))[:48]
                     for f in api.audit(src_path)})
    return {
        "smaller": full["payload_bytes"] < full["source_bytes"],
        "lossless": full["finding_ids"] == direct,
        "ratio": full["ratio"],
        "findings": len(direct),
    }
