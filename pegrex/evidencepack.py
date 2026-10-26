"""Source-bounded compliance evidence packs, never legal conclusions."""
from __future__ import annotations

import hashlib
import re

from .securitycontracts import SecurityContract, check_security_contract

SCHEMA = "pegrex.compliance-evidence-pack.v1"


def create_compliance_pack(source, controls, *, path="<memory>.py") -> dict:
    """Map declared controls to code/data-flow evidence and explicit gaps."""
    rows = []
    for control in controls:
        identifier = control.get("id")
        kind = control.get("kind", "organizational")
        if not identifier:
            rows.append({"id": None, "verdict": "unknown",
                         "provable_from_source": False,
                         "unknowns": ["control without a stable identifier"]})
            continue
        if kind == "flow-contract":
            contract = SecurityContract(identifier,
                tuple(control.get("source_categories") or ()),
                tuple(control.get("sink_categories") or ()),
                tuple(control.get("required_transformations") or ()),
                tuple(control.get("frameworks") or ("shell",)))
            try:
                evidence = check_security_contract(source, contract, path=path)
                rows.append({"id": identifier, "kind": kind,
                             "provable_from_source": True,
                             "verdict": evidence["verdict"], "evidence": evidence,
                             "unknowns": evidence["unknowns"]})
            except Exception as error:
                rows.append({"id": identifier, "kind": kind,
                             "provable_from_source": True, "verdict": "unknown",
                             "unknowns": [f"control evaluation failed: {error}"]})
        elif kind == "source-observation":
            try:
                observed = re.search(control["pattern"], source, re.MULTILINE) is not None
                rows.append({"id": identifier, "kind": kind,
                             "provable_from_source": False,
                             "verdict": "unknown", "observed": observed,
                             "evidence": {"pattern": control["pattern"]},
                             "unknowns": ["source-text observation does not prove operational control effectiveness"]})
            except Exception as error:
                rows.append({"id": identifier, "kind": kind,
                             "provable_from_source": False, "verdict": "unknown",
                             "unknowns": [f"source observation failed: {error}"]})
        else:
            rows.append({"id": identifier, "kind": kind,
                         "provable_from_source": False, "verdict": "unknown",
                         "unknowns": ["organizational, legal, procedural, and runtime controls cannot be proved from source alone"]})
    verdict = ("refuted" if any(row["verdict"] == "refuted" for row in rows) else
               "unknown" if not rows or any(row["verdict"] == "unknown" for row in rows) else "proved")
    return {"schema": SCHEMA, "schema_version": 1, "verdict": verdict,
            "controls": rows, "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
            "unknowns": [f"{row.get('id')}: {reason}" for row in rows for reason in row.get("unknowns", [])],
            "legal_conclusion": None,
            "disclaimer": "Technical source evidence only; not legal advice, certification, attestation, or a compliance conclusion."}
