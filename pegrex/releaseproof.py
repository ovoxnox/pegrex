"""Proof-carrying repository release evidence with machine-checkable UNKNOWNs."""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

from .buildprovenance import create_build_provenance, verify_build_provenance
from .repomemory import RepositoryMemory
from .sbom import generate_sbom
from .semantics import explain_patch

SCHEMA = "pegrex.proof-carrying-release.v1"


def _identity(value) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                    default=str).encode()).hexdigest()


def _unknown_summary(unknowns) -> dict:
    rows = sorted(set(str(row) for row in unknowns))
    categories = Counter(row.split(":", 1)[0] if ":" in row else "general" for row in rows)
    return {"schema": "pegrex.release-unknown-summary.v1", "complete": True,
            "count": len(rows), "by_category": dict(sorted(categories.items())),
            "entries": rows, "summary_sha256": _identity(rows)}


def _contract_release_diff(before, after, before_root, after_root) -> dict:
    rows, unknowns = [], []
    before_apis = before.apis if before else {}
    for key in sorted(set(before_apis) | set(after.apis)):
        old, new = before_apis.get(key), after.apis.get(key)
        if old == new:
            continue
        row = {"api": key, "change": "modified" if old and new else "removed" if old else "added",
               "before_identity": old and old.get("api_identity"),
               "after_identity": new and new.get("api_identity"), "verdict": "unknown"}
        if old and new and old["path"] == new["path"]:
            before_path, after_path = before_root / old["path"], after_root / new["path"]
            try:
                explanation = explain_patch(str(before_path), str(after_path))
                row.update(verdict=explanation["verdict"], evidence=explanation)
                unknowns.extend(f"semantic-diff:{key}:{reason}" for reason in explanation["unknowns"])
            except Exception as error:
                row["unknowns"] = [f"semantic diff failed: {type(error).__name__}: {error}"]
                unknowns.append(f"semantic-diff:{key}:unavailable")
        else:
            unknowns.append(f"semantic-diff:{key}:added or removed API is not equivalence evidence")
        rows.append(row)
    verdict = ("refuted" if any(row["verdict"] == "refuted" for row in rows) else
               "unknown" if unknowns or any(row["verdict"] == "unknown" for row in rows) else "proved")
    return {"schema": "pegrex.release-semantic-diff.v1", "verdict": verdict,
            "changes": rows, "unknowns": sorted(set(unknowns)),
            "before_memory_identity": before and before.memory_identity,
            "after_memory_identity": after.memory_identity}


def _sbom_unknowns(document) -> list[str]:
    if document is None:
        return ["sbom:no supported lockfile supplied"]
    if document.get("bomFormat") == "CycloneDX":
        return ["sbom:" + row["value"] for row in document.get("metadata", {}).get("properties", [])
                if row.get("name") == "pegrex:unknown"]
    comment = json.loads(document.get("documentComment", "{}"))
    return ["sbom:" + row for row in comment.get("unknowns", [])]


def create_proof_carrying_release(root, *, subjects, builder_id, command_argv, build_type,
                                  previous_root=None, lockfile=None, materials=None,
                                  internal_parameters=None) -> dict:
    """Collect independently checkable release sections; never hide missing evidence."""
    root = Path(root).resolve()
    previous = Path(previous_root).resolve() if previous_root is not None else None
    unknowns = []
    try:
        memory = RepositoryMemory(root)
        memory.refresh()
        contracts = []
        for key, api in memory.apis.items():
            verified = api["status"] == "ok" and not api["unknowns"]
            contracts.append({"api": key, "api_identity": api["api_identity"],
                              "source_sha256": api["source_sha256"],
                              "contracts": api["contracts"], "verdict": "proved" if verified else "unknown",
                              "unknowns": list(api["unknowns"]),
                              "verification_scope": "complete registered frontend extraction; not runtime proof"})
            unknowns.extend(f"api-contract:{key}:{reason}" for reason in api["unknowns"])
        unknowns.extend(f"repository:{row}" for row in memory.limitations)

        before_memory = None
        if previous is not None:
            before_memory = RepositoryMemory(previous)
            before_memory.refresh()
            semantic = _contract_release_diff(before_memory, memory, previous, root)
        else:
            semantic = {"schema": "pegrex.release-semantic-diff.v1", "verdict": "unknown",
                        "changes": [], "unknowns": ["previous release root not supplied"],
                        "before_memory_identity": None, "after_memory_identity": memory.memory_identity}
        unknowns.extend("previous-release:" + row for row in semantic["unknowns"])

        sbom = generate_sbom(lockfile) if lockfile is not None else None
        unknowns.extend(_sbom_unknowns(sbom))
        attestation = create_build_provenance(subjects, builder_id=builder_id,
            command_argv=command_argv, build_type=build_type, materials=materials,
            internal_parameters=internal_parameters)
        build_check = verify_build_provenance(attestation, subject_paths=subjects,
                                              material_paths=materials)
        unknowns.extend("build:" + row for row in build_check["unknowns"])
        unknowns.append("build:unsigned attestation does not authenticate builder identity or hermeticity")
        payload = {"schema": SCHEMA, "schema_version": 1,
                   "api_contracts": {"schema": "pegrex.release-api-contracts.v1",
                       "memory_identity": memory.memory_identity, "entries": contracts,
                       "verification_scope": "source contracts and content identities"},
                   "sbom": sbom,
                   "sbom_sha256": _identity(sbom) if sbom is not None else None,
                   "build_attestation": attestation, "build_verification": build_check,
                   "semantic_diff": semantic}
        payload["release_identity"] = _identity(payload)
        payload["unknown_summary"] = _unknown_summary(unknowns)
        payload["verdict"] = "unknown" if unknowns else "proved"
        payload["scope"] = "release evidence and hash verification; unsigned provenance is not builder authentication"
        return payload
    except Exception as error:
        unknowns.append(f"release:evidence creation failed: {type(error).__name__}: {error}")
        return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown",
                "unknown_summary": _unknown_summary(unknowns)}


def verify_release_pack(pack, root, *, previous_root=None, lockfile=None,
                        subject_paths=None, material_paths=None) -> dict:
    """Recheck artifact identities and all available upstream evidence."""
    unknowns = []
    try:
        if pack.get("schema") != SCHEMA:
            raise ValueError("unsupported release evidence schema")
        identity_payload = {key: pack[key] for key in (
            "schema", "schema_version", "api_contracts", "sbom", "sbom_sha256",
            "build_attestation", "build_verification", "semantic_diff")}
        if _identity(identity_payload) != pack.get("release_identity"):
            return {"schema": SCHEMA, "verified": False, "verdict": "refuted",
                    "unknowns": ["release identity mismatch"]}
        memory = RepositoryMemory(Path(root).resolve())
        memory.refresh()
        if memory.memory_identity != pack["api_contracts"].get("memory_identity"):
            return {"schema": SCHEMA, "verified": False, "verdict": "refuted",
                    "unknowns": ["API contract memory identity mismatch"]}
        if pack.get("sbom") is None:
            unknowns.append("sbom:no supported lockfile supplied")
        elif lockfile is not None:
            regenerated = generate_sbom(lockfile)
            if _identity(regenerated) != pack.get("sbom_sha256"):
                return {"schema": SCHEMA, "verified": False, "verdict": "refuted",
                        "unknowns": ["SBOM identity mismatch"]}
        else:
            unknowns.append("sbom:upstream lockfile not supplied for independent regeneration")
        build = verify_build_provenance(pack["build_attestation"],
            subject_paths=subject_paths, material_paths=material_paths)
        if build["verdict"] == "refuted":
            return {"schema": SCHEMA, "verified": False, "verdict": "refuted",
                    "unknowns": ["build subject or material hash mismatch"]}
        unknowns.extend("build:" + row for row in build["unknowns"])
        unknowns.append("build:unsigned attestation does not authenticate builder identity or hermeticity")
        if previous_root is not None:
            before = RepositoryMemory(Path(previous_root).resolve())
            before.refresh()
            semantic = _contract_release_diff(before, memory, Path(previous_root).resolve(), Path(root).resolve())
            if _identity(semantic) != _identity(pack["semantic_diff"]):
                return {"schema": SCHEMA, "verified": False, "verdict": "refuted",
                        "unknowns": ["semantic diff evidence mismatch"]}
        else:
            unknowns.append("previous-release:not independently reverified")
        unknowns.extend(pack.get("unknown_summary", {}).get("entries", []))
        summary = _unknown_summary(unknowns)
        return {"schema": SCHEMA, "verified": not unknowns, "verdict": "unknown" if unknowns else "proved",
                "release_identity": pack["release_identity"], "build_verification": build,
                "unknown_summary": summary}
    except Exception as error:
        return {"schema": SCHEMA, "verified": False, "verdict": "unknown",
                "unknowns": [f"release verification failed: {type(error).__name__}: {error}"]}
