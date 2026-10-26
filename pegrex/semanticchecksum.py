"""Cross-language semantic checksums over contracts, domains, and effects."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .effects import infer_effects
from .languages import normalize_language
from .semantics import contracts_of, explain_patch

SCHEMA = "pegrex.semantic-checksum.v1"


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _identity(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def _semantic_effects(report):
    """Drop source coordinates so comments and formatting do not change semantics."""
    def clean(value):
        """Implement clean with the module's explicit API and failure semantics."""
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items()
                    if key not in {"line", "end_line"}}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value
    return clean(report["functions"])


def semantic_checksum(source_path, *, language=None, type_assumptions=None,
                      domain_assumptions=None) -> dict:
    """Serialize normalized behavior independently of surface source syntax."""
    path = Path(source_path)
    unknowns = []
    try:
        lang = normalize_language(language or path.suffix.lstrip("."))
        contracts = [{"constraints": sorted(constraints), "result": result}
                     for constraints, result in sorted(contracts_of(str(path)), key=lambda row: (sorted(row[0]), row[1]))]
        effects = None
        if lang == "python":
            try:
                report = infer_effects(path.read_text(encoding="utf-8"), language=lang)
                effects = _semantic_effects(report)
                unknowns.extend(report.get("unknowns") or [])
            except Exception as error:
                unknowns.append(f"effect summary unavailable: {type(error).__name__}: {error}")
        else:
            unknowns.append(f"explicit effect summary unavailable for {lang}")
        payload = {"schema": "pegrex.normalized-semantic-payload.v1", "language": lang,
                   "contracts": contracts,
                   "type_assumptions": type_assumptions or {},
                   "domain_assumptions": domain_assumptions or {},
                   "effects": effects}
        checksum = _identity(payload)
        return {"schema": SCHEMA, "schema_version": 1, "semantic_checksum": checksum,
                "serialization": _canonical(payload), "payload": payload,
                "source_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "verdict": "unknown" if unknowns else "proved", "unknowns": sorted(set(unknowns)),
                "scope": "registered normalized contracts and explicit assumptions/effects; not whole-program equivalence"}
    except Exception as error:
        return {"schema": SCHEMA, "schema_version": 1, "semantic_checksum": None,
                "verdict": "unknown", "unknowns": [f"semantic checksum failed: {type(error).__name__}: {error}"]}


def diff_semantic_checksums(before, after) -> dict:
    """Diff checksum components without asserting an unconfirmed behavior break."""
    try:
        for report in (before, after):
            if report.get("schema") != SCHEMA or not report.get("semantic_checksum"):
                raise ValueError("complete semantic checksum reports required")
            if _identity(report["payload"]) != report["semantic_checksum"]:
                return {"schema": "pegrex.semantic-checksum-diff.v1", "verdict": "refuted",
                        "unknowns": [], "reason": "checksum payload identity mismatch"}
        components = [key for key in ("contracts", "type_assumptions", "domain_assumptions", "effects")
                      if before["payload"].get(key) != after["payload"].get(key)]
        same = before["semantic_checksum"] == after["semantic_checksum"]
        unknowns = sorted(set(before.get("unknowns", []) + after.get("unknowns", [])))
        if not same and not components:
            unknowns.append("checksum differs without a localized component difference")
        return {"schema": "pegrex.semantic-checksum-diff.v1",
                "identical": same, "changed_components": components,
                "before_checksum": before["semantic_checksum"], "after_checksum": after["semantic_checksum"],
                "verdict": "unknown" if unknowns or not same else "proved",
                "unknowns": unknowns + ([] if same else ["semantic checksum mismatch is not itself a confirmed behavioral counterexample"]),
                "scope": "normalized semantic component diff only"}
    except Exception as error:
        return {"schema": "pegrex.semantic-checksum-diff.v1", "verdict": "unknown",
                "identical": False, "changed_components": [], "unknowns": [str(error)]}


def semantic_checksum_diff(before_path, after_path, **kwargs) -> dict:
    """Attach path-specific proof/counterexample evidence to the checksum diff."""
    before = semantic_checksum(before_path, **kwargs)
    after = semantic_checksum(after_path, **kwargs)
    result = diff_semantic_checksums(before, after)
    try:
        evidence = explain_patch(str(before_path), str(after_path))
        result["semantic_evidence"] = evidence
        result["verdict"] = evidence["verdict"]
        result["unknowns"] = sorted(set(result["unknowns"] + evidence["unknowns"]))
    except Exception as error:
        result["verdict"] = "unknown"
        result["unknowns"] = sorted(set(result["unknowns"] + [f"semantic confirmation unavailable: {error}"]))
    return result
