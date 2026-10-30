"""Bind integration claims to exact source/backend/artifact identities."""
from __future__ import annotations

from . import SCHEMA


def assurance_claim(result: dict, claim_id: str, statement: str, *,
                    kind: str = "api-contract") -> dict:
    """Convert one integration result into a continuous-assurance claim.

    Candidate and incomplete results remain UNKNOWN. Every evidence row depends
    on the exact generated artifact hashes, so source/toolchain changes can be
    invalidated by the existing assurance graph rather than silently persisting.
    """
    unknowns = list(result.get("unknowns") or [])
    artifacts = result.get("artifacts") or []
    verdict = result.get("verdict") if result.get("verdict") in {"proved", "refuted", "unknown"} else "unknown"
    if verdict == "proved" and not artifacts:
        verdict = "unknown"
        unknowns.append("a proved integration claim requires exact artifact identities")
    evidence = []
    if artifacts:
        upstream = [{"id": f"artifact:{row['path']}:{row['sha256']}",
                     "path": row["path"], "sha256": row["sha256"]}
                    for row in artifacts]
        evidence.append({"id": f"integration:{result.get('backend')}:{result.get('operation')}",
                         "verdict": verdict, "upstream": upstream})
    elif verdict != "proved":
        evidence.append({"id": f"integration:{result.get('backend')}:{result.get('operation')}",
                         "verdict": "unknown", "upstream": []})
    return {"schema": SCHEMA, "schema_version": 1, "id": claim_id, "kind": kind,
            "statement": statement, "verdict": verdict, "evidence": evidence,
            "unknowns": sorted(set(unknowns))}
