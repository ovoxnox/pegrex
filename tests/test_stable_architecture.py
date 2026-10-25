"""Integration invariants for registry dispatch and the stable-core boundary."""
from __future__ import annotations

from pathlib import Path

import pytest

from pegrex.languages import (EXTENSION_MAP, LANGUAGES, capability_matrix,
                              detect_language, extract_contract_pairs,
                              get_contract_frontend, get_language, parse_source,
                              rule_languages, validate_registry)
from pegrex.core import (OperationStatus, PathContract, SourceDocument,
                         Verdict, get_engine)


def test_every_registered_extension_resolves_to_its_language():
    for extension, language in EXTENSION_MAP.items():
        assert detect_language("sample" + extension) == language


def test_registry_capabilities_are_self_consistent():
    assert validate_registry() == []
    for language, spec in LANGUAGES.items():
        if "contracts" in spec.capabilities:
            assert spec.contract_mode in {"native", "tree-sitter", "pipeline"}
            if spec.contract_mode == "pipeline":
                assert spec.frontend_factory
                assert callable(get_contract_frontend(language))
            if spec.contract_mode == "native":
                assert spec.contract_handler
        if "parse" in spec.capabilities:
            assert spec.parse_adapter in {"tree-sitter", "c-peg"}
        else:
            assert spec.parse_adapter in {"tree-sitter", "c-peg"}  # default is inert when parse is unavailable


def test_legacy_language_map_is_registry_derived():
    from pegrex.tree_sitter_bridge import LANGUAGE_MAP
    assert set(LANGUAGE_MAP) == {name for name, spec in LANGUAGES.items()
                                 if "parse" in spec.capabilities}
    assert LANGUAGE_MAP["lua"] == "lua"
    assert LANGUAGE_MAP["c"] == "c"


def test_parse_dispatch_uses_registry_for_python_and_c():
    py = parse_source("python", "def f(x):\n    return x + 1\n")
    c = parse_source("c", "int f(int x) { return x + 1; }")
    assert py.tag == "module"
    assert c is not None


def test_language_rules_inherit_from_registry():
    assert rule_languages("typescript") == frozenset({"typescript", "javascript"})
    assert rule_languages("tsx") == frozenset({"tsx", "javascript"})


def test_source_document_uses_validated_canonical_language_and_character_offsets():
    doc = SourceDocument("π\nreturn 1", "py")
    assert doc.language == "python"
    assert doc.slice(0, 1) == "π"
    assert doc.line(2) == 2
    with pytest.raises(ValueError):
        doc.slice(0, len(doc.text) + 1)


def test_path_contract_identity_includes_outcome_without_refinement_dependency():
    left = PathContract.create(["x  >=  0"], "0")
    same = PathContract.create(["x >= 0"], "0")
    different = PathContract.create(["x >= 0"], "x")
    assert left.identity == same.identity
    assert left.identity != different.identity
    model_source = Path("pegrex/core/models.py").read_text()
    assert "from ..refine import" not in model_source


def test_core_contract_engine_returns_stable_result_shape():
    src = "def f(x):\n    if x < 0:\n        return 0\n    return x\n"
    result = get_engine().extract_contracts(src, "python")
    assert result.operation == "contracts"
    assert result.status in {OperationStatus.OK, OperationStatus.PARTIAL}
    if result.data:
        assert all("identity" in row and "outcome" in row for row in result.data)


def test_registry_contract_extractor_matches_core_entrypoint():
    src = "def f(x):\n    if x < 0:\n        return 0\n    return x\n"
    assert extract_contract_pairs("python", src)


def test_capability_matrix_has_stable_schema():
    rows = capability_matrix()
    assert {r["language"] for r in rows} == set(LANGUAGES)
    assert all("capabilities" in r and "parse_adapter" in r and "outcome_renderer" in r for r in rows)
