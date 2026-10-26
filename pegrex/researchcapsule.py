"""Deterministic content-addressed security research capsules."""
from __future__ import annotations

import hashlib
import io
import json
import zipfile
from pathlib import Path, PurePosixPath

from .kernel import check_certificate
from .regressionmemory import register_finding_fix

SCHEMA = "pegrex.security-research-capsule.v1"


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _json_bytes(value):
    return (json.dumps(value, sort_keys=True, indent=2, default=str) + "\n").encode()


def _identity(value):
    return _sha(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode())


def create_research_capsule(output, *, finding, minimized_source, fixed_source,
                            exploit_preconditions, sandbox_argv, regression_test_path=None,
                            minimization_evidence=None, proof_or_witness=None) -> dict:
    """Package finding-to-fix evidence without executing the exploit recipe."""
    unknowns = []
    try:
        if isinstance(sandbox_argv, str) or not sandbox_argv or any(not isinstance(row, str) for row in sandbox_argv):
            raise ValueError("sandbox recipe requires structured argv")
        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        test_name = PurePosixPath(regression_test_path or "regression_test.py").name
        memory_name = "regression_memory.json"
        registration = register_finding_fix(finding, minimized_source, fixed_source,
                                            output.parent / (output.stem + "." + test_name),
                                            output.parent / (output.stem + "." + memory_name))
        if registration["status"] != "registered":
            return {"schema": SCHEMA, "status": "unknown", "verdict": "unknown",
                    "unknowns": registration["unknowns"] + ["capsule not created"]}
        test_path = Path(registration["entry"]["test_path"])
        generated_memory_path = output.parent / (output.stem + "." + memory_name)
        memory_document = json.loads(generated_memory_path.read_text(encoding="utf-8"))
        for entry in memory_document["entries"]:
            entry["test_path"] = test_name
        test_bytes = test_path.read_bytes()
        memory_bytes = _json_bytes(memory_document)
        test_path.unlink(); generated_memory_path.unlink()
        if not minimization_evidence or not minimization_evidence.get("confirmed"):
            unknowns.append("source minimization is declared but not independently confirmed")
        proof_status = "unknown"
        if proof_or_witness:
            certificate = proof_or_witness.get("certificate")
            if certificate:
                checked = check_certificate(certificate)
                proof_status = "verified" if checked.get("verdict") == "proved" else "unknown"
                if proof_status != "verified":
                    unknowns.append("supplied certificate did not pass the minimal kernel")
            elif (proof_or_witness.get("counterexample") or {}).get("confirmed"):
                proof_status = "confirmed-witness"
            else:
                unknowns.append("proof/witness evidence is unconfirmed")
        else:
            unknowns.append("proof or confirmed witness not supplied")
        recipe = {"schema": "pegrex.capsule-sandbox-recipe.v1", "argv": list(sandbox_argv),
                  "files": {"vulnerable.min": "vulnerable.min", "regression_test.py": test_name},
                  "timeout_ms": 5000, "memory_mb": 256, "network": "disabled",
                  "credentials": "none", "execution": "not-requested",
                  "backend": "ephemeral bubblewrap+prlimit required"}
        files = {"finding.json": _json_bytes(finding), "vulnerable.min": minimized_source.encode(),
                 "fixed.py": fixed_source.encode(),
                 "exploit-preconditions.json": _json_bytes(exploit_preconditions),
                 "sandbox-recipe.json": _json_bytes(recipe), test_name: test_bytes,
                 memory_name: memory_bytes,
                 "proof-or-witness.json": _json_bytes(proof_or_witness),
                 "minimization-evidence.json": _json_bytes(minimization_evidence)}
        entries = [{"path": name, "sha256": _sha(data), "bytes": len(data)}
                   for name, data in sorted(files.items())]
        manifest_payload = {"schema": SCHEMA, "schema_version": 1,
                            "finding_id": finding.get("id"), "artifacts": entries,
                            "sandbox_recipe_sha256": _sha(files["sandbox-recipe.json"]),
                            "proof_status": proof_status,
                            "source_minimized": bool(minimization_evidence and minimization_evidence.get("confirmed"))}
        manifest_payload["capsule_identity"] = _identity(manifest_payload)
        manifest = dict(manifest_payload, unknowns=sorted(set(unknowns)),
                        scope="content-addressed research evidence; recipe inclusion is not execution or exploit confirmation")
        manifest_bytes = _json_bytes(manifest)
        with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
            for name, data in sorted(files.items()):
                info = zipfile.ZipInfo(name, (1980, 1, 1, 0, 0, 0))
                info.compress_type = zipfile.ZIP_DEFLATED; info.external_attr = 0o600 << 16
                archive.writestr(info, data)
            info = zipfile.ZipInfo("manifest.json", (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED; info.external_attr = 0o600 << 16
            archive.writestr(info, manifest_bytes)
        return {"schema": SCHEMA, "status": "created", "verdict": "unknown" if unknowns else "proved",
                "path": str(output), "capsule_identity": manifest["capsule_identity"],
                "artifact_sha256": _sha(output.read_bytes()), "unknowns": manifest["unknowns"]}
    except Exception as error:
        return {"schema": SCHEMA, "status": "unknown", "verdict": "unknown",
                "unknowns": [f"capsule creation failed: {type(error).__name__}: {error}"]}


def verify_research_capsule(path) -> dict:
    """Verify containment, manifest identity, every artifact hash, and negative control."""
    unknowns = []
    try:
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            if len(names) != len(set(names)) or any(PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts
                                                    for name in names):
                raise ValueError("unsafe or duplicate capsule path")
            manifest = json.loads(archive.read("manifest.json"))
            payload = {key: manifest[key] for key in ("schema", "schema_version", "finding_id", "artifacts",
                       "sandbox_recipe_sha256", "proof_status", "source_minimized")}
            if payload["schema"] != SCHEMA or _identity(payload) != manifest.get("capsule_identity"):
                return {"schema": SCHEMA, "verified": False, "verdict": "refuted", "unknowns": ["capsule identity mismatch"]}
            for row in manifest["artifacts"]:
                data = archive.read(row["path"])
                if _sha(data) != row["sha256"] or len(data) != row["bytes"]:
                    return {"schema": SCHEMA, "verified": False, "verdict": "refuted",
                            "unknowns": [f"artifact hash mismatch: {row['path']}"]}
            finding = json.loads(archive.read("finding.json"))
            vulnerable = archive.read("vulnerable.min").decode()
            fixed = archive.read("fixed.py").decode()
            from .flow import analyze_source
            if finding["id"] not in {row["id"] for row in analyze_source(vulnerable)["findings"]}:
                return {"schema": SCHEMA, "verified": False, "verdict": "refuted",
                        "unknowns": ["original finding negative control no longer reproduces"]}
            if finding["id"] in {row["id"] for row in analyze_source(fixed)["findings"]}:
                return {"schema": SCHEMA, "verified": False, "verdict": "refuted",
                        "unknowns": ["fixed source still triggers original finding"]}
            recipe = json.loads(archive.read("sandbox-recipe.json"))
            if recipe.get("network") != "disabled" or recipe.get("credentials") != "none":
                return {"schema": SCHEMA, "verified": False, "verdict": "refuted",
                        "unknowns": ["unsafe sandbox recipe"]}
            unknowns.extend(manifest.get("unknowns") or [])
            unknowns.append("sandbox recipe was not executed by capsule verification")
            return {"schema": SCHEMA, "verified": not unknowns, "verdict": "unknown" if unknowns else "proved",
                    "capsule_identity": manifest["capsule_identity"],
                    "artifacts_verified": len(manifest["artifacts"]), "unknowns": sorted(set(unknowns))}
    except Exception as error:
        return {"schema": SCHEMA, "verified": False, "verdict": "unknown",
                "unknowns": [f"capsule verification failed: {type(error).__name__}: {error}"]}
