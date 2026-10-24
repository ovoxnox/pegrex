from pegrex.contract import (KIND_ORDER, StructuralError, manifest_contract,
                             validate_contract)


def MANIFEST(**kw):
    base = {
        "bundle": {"id": "my-ext", "version": "1.0.0", "effect": "read-write"},
        "requires": {"engine_version": "1.0.0"},
        "provides": {"commands": [{"name": "audit", "description": "run audit"}]},
    }
    base.update(kw)
    return base


def test_valid_manifest_passes():
    assert validate_contract(MANIFEST(), [manifest_contract]) == []


def test_null_counts_as_missing():
    spec = MANIFEST()
    spec["bundle"]["license"] = None
    errs = validate_contract(spec, [manifest_contract])
    assert not any(e.path == "bundle.license" for e in errs)  # null optional ok
    spec["bundle"]["version"] = None
    errs = validate_contract(spec, [manifest_contract])
    assert any("bundle.version" == e.path and "required" in e.message for e in errs)


def test_semver_actionable():
    spec = MANIFEST()
    spec["bundle"]["version"] = "1.0"
    errs = validate_contract(spec, [manifest_contract])
    assert any(e.path == "bundle.version" and "semver" in e.message for e in errs)


def test_string_where_list_rejected_not_split():
    spec = MANIFEST()
    spec["provides"]["commands"] = "single-string"
    errs = validate_contract(spec, [manifest_contract])
    assert any("not split per character" in e.message for e in errs)


def test_non_mapping_including_falsy():
    for falsy in ({}, 0, "", []):
        spec = MANIFEST()
        spec["provides"] = falsy
        errs = validate_contract(spec, [manifest_contract])
        assert any("provides" in e.path for e in errs), falsy


def test_kind_ordering():
    spec = MANIFEST()
    spec["components"] = [
        {"kind": "workflows", "id": "w", "version": "1.0.0"},
        {"kind": "extensions", "id": "e", "version": "1.0.0"},
    ]
    errs = validate_contract(spec, [manifest_contract])
    assert any("order by kind" in e.message for e in errs)


def test_non_step_must_be_pinned():
    spec = MANIFEST()
    spec["components"] = [{"kind": "workflows", "id": "w"}]
    errs = validate_contract(spec, [manifest_contract])
    assert any("must be pinned" in e.message for e in errs)
    spec["components"] = [{"kind": "steps", "id": "s"}]
    assert validate_contract(spec, [manifest_contract]) == []


def test_slug_safety():
    spec = MANIFEST()
    spec["bundle"]["id"] = "Bad Slug!"
    errs = validate_contract(spec, [manifest_contract])
    assert any(e.path == "bundle.id" and "slug" in e.message for e in errs)


def test_effect_enum():
    spec = MANIFEST()
    spec["bundle"]["effect"] = "side-channel"
    errs = validate_contract(spec, [manifest_contract])
    assert any(e.path == "bundle.effect" for e in errs)


def test_errors_are_addressable():
    spec = MANIFEST()
    spec["bundle"]["version"] = None
    errs = validate_contract(spec, [manifest_contract])
    assert all(isinstance(e, StructuralError) and "." in e.path for e in errs)
