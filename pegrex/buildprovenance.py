"""In-toto statements with SLSA v1 provenance and verifiable subjects."""
from __future__ import annotations
import hashlib, json, os
from pathlib import Path
SCHEMA = "https://in-toto.io/Statement/v1"
PREDICATE = "https://slsa.dev/provenance/v1"


def _paths(values):
    if isinstance(values, dict): return dict(values)
    result = {}
    for value in values or []:
        path = Path(value)
        if path.name in result: raise ValueError("subject/material names must be unique")
        result[path.name] = path
    return result

def _subjects(values):
    rows = []
    for name, path in sorted(_paths(values).items()):
        raw = Path(path).read_bytes()
        rows.append({"name": name, "digest": {"sha256": hashlib.sha256(raw).hexdigest()}})
    return rows

def create_build_provenance(subjects, *, builder_id, command_argv, build_type,
                            materials=None, internal_parameters=None) -> dict:
    """Create an unsigned local statement; builder authentication is not claimed."""
    if isinstance(command_argv, str) or not command_argv or any(not isinstance(row, str) for row in command_argv):
        raise ValueError("build command must be a nonempty argv sequence")
    subject_rows = _subjects(subjects)
    if not subject_rows: raise ValueError("at least one verifiable subject is required")
    dependencies = []
    for uri, path in sorted(_paths(materials).items()):
        raw = Path(path).read_bytes()
        dependencies.append({"uri": uri, "digest": {"sha256": hashlib.sha256(raw).hexdigest()}})
    predicate = {"buildDefinition": {"buildType": build_type,
        "externalParameters": {"command": list(command_argv)},
        "internalParameters": internal_parameters or {}, "resolvedDependencies": dependencies},
        "runDetails": {"builder": {"id": builder_id},
            "metadata": {"invocationId": "local-unauthenticated"},
            "byproducts": []}}
    return {"_type": SCHEMA, "subject": subject_rows, "predicateType": PREDICATE,
            "predicate": predicate}


def verify_build_provenance(statement, *, subject_paths=None, material_paths=None) -> dict:
    """Verify statement structure and hashes; UNSIGNED builder identity is not authenticated."""
    unknowns = []
    try:
        if statement.get("_type") != SCHEMA or statement.get("predicateType") != PREDICATE:
            return {"verified": False, "verdict": "unknown", "unknowns": ["unsupported statement"]}
        subjects = statement["subject"]
        if not isinstance(subjects, list) or not subjects: raise ValueError("subjects missing")
        paths = _paths(subject_paths if subject_paths is not None else {row["name"]: row["name"] for row in subjects})
        for row in subjects:
            name, expected = row["name"], row["digest"]["sha256"]
            if name not in paths or not Path(paths[name]).is_file():
                unknowns.append(f"subject unavailable: {name}"); continue
            actual = hashlib.sha256(Path(paths[name]).read_bytes()).hexdigest()
            if actual != expected:
                return {"verified": False, "verdict": "refuted", "subject": name,
                        "expected_sha256": expected, "actual_sha256": actual, "unknowns": unknowns}
        materials = statement["predicate"]["buildDefinition"].get("resolvedDependencies", [])
        material_paths = _paths(material_paths)
        for row in materials:
            uri = row["uri"]
            if uri not in material_paths:
                unknowns.append(f"material not reverified: {uri}"); continue
            actual = hashlib.sha256(Path(material_paths[uri]).read_bytes()).hexdigest()
            if actual != row["digest"]["sha256"]:
                return {"verified": False, "verdict": "refuted", "material": uri, "unknowns": unknowns}
        return {"verified": not unknowns, "verdict": "unknown" if unknowns else "proved",
                "subjects": len(subjects), "materials": len(materials), "unknowns": unknowns,
                "authentication": "unsigned; only structure and available subject/material hashes verified"}
    except (KeyError, TypeError, ValueError, OSError, AttributeError) as error:
        return {"verified": False, "verdict": "unknown", "unknowns": [f"malformed provenance: {error}"]}
