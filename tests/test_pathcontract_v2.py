from pegrex.pathcontract_v2 import SCHEMA, validate_path_contract_v2


def record(**updates):
    value = {
        "schema": SCHEMA,
        "schema_version": 2,
        "source": {
            "path": "src/example.py",
            "sha256": "a" * 64,
            "span": {"start": 0, "end": 12, "unit": "unicode-codepoint",
                     "convention": "zero-based-half-open"},
        },
        "function": "example",
        "guards": ["x >= 0"],
        "outcome": {"kind": "return", "expression": "x"},
        "effects": [],
        "nondeterministic": False,
        "termination": {"status": "not-claimed"},
        "numeric_semantics": {"integer": "unbounded", "overflow": "not-applicable",
                              "floating_point": "not-applicable"},
        "unknowns": [],
    }
    value.update(updates)
    return value


def test_v2_valid_record_is_described_not_proved():
    result = validate_path_contract_v2(record())
    assert result["valid"] is True
    assert result["completeness"] == "described"
    assert result["is_proof"] is False


def test_unknown_is_preserved_as_incomplete():
    value = record(unknowns=["dynamic call target not resolved"])
    result = validate_path_contract_v2(value)
    assert result["valid"] is True
    assert result["completeness"] == "unknown"


def test_unicode_span_convention_and_bounds_are_strict():
    value = record()
    value["source"]["span"]["unit"] = "utf8-byte"
    value["source"]["span"]["start"] = -1
    result = validate_path_contract_v2(value)
    assert not result["valid"]
    assert any("unicode-codepoint" in error for error in result["errors"])
    assert any("non-negative integer" in error for error in result["errors"])


def test_raise_requires_exception_type_and_effects_are_unique():
    value = record(outcome={"kind": "raise"}, effects=["io", "io"])
    result = validate_path_contract_v2(value)
    assert not result["valid"]
    assert any("exception_type" in error for error in result["errors"])
    assert any("duplicate effects" in error for error in result["errors"])


def test_numeric_unknown_and_unknown_outcome_never_look_complete():
    value = record(outcome={"kind": "unknown"})
    value["numeric_semantics"]["integer"] = "unknown"
    result = validate_path_contract_v2(value)
    assert result["valid"] is True
    assert result["completeness"] == "unknown"


def test_unknown_fields_and_non_objects_fail_closed():
    assert not validate_path_contract_v2([])["valid"]
    value = record(looks_proven=True)
    result = validate_path_contract_v2(value)
    assert not result["valid"]
    assert any("unsupported fields" in error for error in result["errors"])
