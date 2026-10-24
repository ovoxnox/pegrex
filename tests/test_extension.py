import json
import pathlib
import tempfile

from pegrex.extension import (ExtensionError, installed_capabilities,
                              load_extension, wrap_catalog)

ROOT = pathlib.Path(__file__).parent.parent


def _write(tmp_path, obj):
    p = tmp_path / "ext.json"
    p.write_text(json.dumps(obj))
    return p


def _good_manifest():
    return {"bundle": {"id": "my-pack", "version": "1.0.0", "effect": "read"},
            "requires": {"engine_version": "1.0.0"},
            "provides": {"commands": [{"name": "audit", "description": "d"}]}}


def test_load_combined_extension(tmp_path=None):
    tmp_path = tmp_path or pathlib.Path(tempfile.mkdtemp())
    p = _write(tmp_path, {"manifest": _good_manifest(),
                          "rules": [{"id": "R1"}]})
    ext = load_extension(p)
    assert ext.id == "my-pack" and ext.commands == ["audit"]
    assert ext.rules == [{"id": "R1"}]


def test_invalid_manifest_rejected(tmp_path=None):
    tmp_path = tmp_path or pathlib.Path(tempfile.mkdtemp())
    bad = _good_manifest()
    bad["bundle"]["version"] = "1.0"
    p = _write(tmp_path, {"manifest": bad, "rules": []})
    try:
        load_extension(p)
        assert False, "should raise"
    except ExtensionError as e:
        assert "semver" in str(e)


def test_wrap_catalog_roundtrip(tmp_path=None):
    tmp_path = tmp_path or pathlib.Path(tempfile.mkdtemp())
    wrapped = wrap_catalog(ROOT / "pegrex/secrules_taint.json",
                           "taint-pack", "2.1.0")
    p = _write(tmp_path, wrapped)
    ext = load_extension(p)
    assert ext.id == "taint-pack" and ext.version == "2.1.0"
    import json
    n = len(json.loads((ROOT / 'pegrex/secrules_taint.json').read_text())['rules'])
    assert len(ext.rules) == n and len(ext.commands) == n


def test_installed_capabilities_index():
    from pegrex.extension import Extension
    a = Extension(_good_manifest() | {"bundle": {"id": "a", "version": "1.0.0",
                                                  "effect": "read",
                                                  "requires": {"engine_version": "1.0.0"},
                                                  "provides": {"commands": [
                                                      {"name": "audit", "description": "d"}]}}})
    caps = installed_capabilities([a])
    assert caps == {"audit": ["a"]}
