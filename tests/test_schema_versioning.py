from __future__ import annotations

import json
import subprocess
import sys

import pytest

from pegrex.incremental import IncrementalContractExtractor
from pegrex.schema import (CERTIFICATE, CLI_ENVELOPE, CONTRACT, FINDING, UNKNOWN,
                           certificate_document, cli_envelope, contract_document,
                           finding_document, schema_catalog, unknown_document,
                           validate_document)


def test_stable_finding_contract_and_unknown_documents_validate():
    finding = finding_document({
        "id": "rule", "severity": "HIGH", "confidence": "high", "line": 1,
        "evidence": "eval(x)", "kind": "pattern", "suppressed": False})
    contract = contract_document(constraints={"x >= 0"}, outcome="x")
    unknown = unknown_document("parser unavailable", source="a.py", resource="parser")
    assert finding["schema"] == FINDING
    assert contract["schema"] == CONTRACT
    assert unknown["schema"] == UNKNOWN
    for document in (finding, contract, unknown):
        assert document["schema_version"] == 1
        assert validate_document(document) == []


def test_certificate_trust_invariant_is_schema_enforced():
    proved = certificate_document("proved", "equivalent", evidence={"proof": "fm-1"})
    refuted = certificate_document(
        "refuted", "equivalent", counterexample={"confirmed": True, "args": [1]})
    unknown = certificate_document("unknown", "equivalent", unknowns=["solver timeout"])
    for document in (proved, refuted, unknown):
        assert document["schema"] == CERTIFICATE
        assert validate_document(document) == []
    with pytest.raises(ValueError, match="cannot contain UNKNOWN"):
        certificate_document("proved", "equivalent", unknowns=["incomplete paths"])
    with pytest.raises(ValueError, match="confirmed counterexample"):
        certificate_document("refuted", "equivalent", counterexample={"confirmed": False})


def test_packaged_json_schemas_match_central_catalog():
    from pathlib import Path
    catalog = schema_catalog()
    for schema, definition in catalog.items():
        path = Path(__file__).parent.parent / "pegrex" / "jsonschemas" / (
            schema.removeprefix("pegrex.") + ".json")
        assert json.loads(path.read_text()) == definition


def test_cli_json_is_backwards_compatible_with_opt_in_envelope(tmp_path):
    source = tmp_path / "safe.py"
    source.write_text("value = 1\n")
    base = [sys.executable, "-m", "pegrex.cli", "audit", str(source), "--json"]
    legacy = subprocess.run(base, capture_output=True, text=True)
    assert legacy.returncode == 0, legacy.stderr
    document = json.loads(legacy.stdout)
    assert document["schema"] == "pegrex.security-scan.v1"
    assert "data" not in document
    assert all(row["schema"] == FINDING for row in document["findings"])
    assert all(row["schema"] == UNKNOWN for row in document["unknowns"])

    wrapped = subprocess.run(base + ["--schema-envelope"], capture_output=True, text=True)
    assert wrapped.returncode == 0, wrapped.stderr
    envelope = json.loads(wrapped.stdout)
    assert envelope["schema"] == CLI_ENVELOPE
    assert envelope["command"] == "audit"
    assert envelope["data"]["schema"] == "pegrex.security-scan.v1"
    assert validate_document(envelope) == []


def test_incremental_contracts_use_versioned_public_rows(tmp_path):
    path = str(tmp_path / "module.py")
    extractor = IncrementalContractExtractor()
    extractor.update(path, "def f(x):\n    return x\n")
    row = extractor.get(path, "f")["contracts"][0]
    assert row["schema"] == CONTRACT
    assert validate_document(row) == []
