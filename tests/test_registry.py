import json
import pathlib
import tempfile

from pegrex.registry import (certify_package, find_regressions, load_registry,
                             publish, save_registry, verify_package)

KEY = "k"
V1 = "def clamp_nonneg(n):\n    if n < 0:\n        return 0\n    return n\n"
V2_BROKEN = "def clamp_nonneg(n):\n    return n\n"


def test_certify_package_signs_a_manifest():
    m = certify_package("p", "1.0.0", {"a.py": V1}, KEY)
    assert m["name"] == "p" and m["version"] == "1.0.0"
    assert m["certified"]["a.py"]["proven"]
    assert verify_package(m, KEY)["ok"] is True


def test_verify_package_rejects_wrong_key():
    m = certify_package("p", "1.0.0", {"a.py": V1}, KEY)
    assert verify_package(m, "wrong")["ok"] is False


def test_find_regressions_empty_for_identical_manifests():
    m = certify_package("p", "1.0.0", {"a.py": V1}, KEY)
    assert find_regressions(m, m) == []


def test_find_regressions_names_lost_property():
    old = certify_package("p", "1.0.0", {"a.py": V1}, KEY)
    new = certify_package("p", "2.0.0", {"a.py": V2_BROKEN}, KEY)
    regs = find_regressions(old, new)
    assert any(r["property"] == "result >= 0" for r in regs)


def test_find_regressions_removed_file_loses_everything():
    old = certify_package("p", "1.0.0", {"a.py": V1}, KEY)
    new = certify_package("p", "2.0.0", {}, KEY)
    regs = find_regressions(old, new)
    assert len(regs) == len(old["certified"]["a.py"]["proven"])


def test_publish_first_version_always_succeeds():
    with tempfile.TemporaryDirectory() as td:
        path = str(pathlib.Path(td) / "r.json")
        out = publish("p", "1.0.0", {"a.py": V1}, KEY, path)
        assert out["status"] == "published"
        assert load_registry(path)["p"]["version"] == "1.0.0"


def test_publish_refuses_a_regression_and_registry_stays_put():
    with tempfile.TemporaryDirectory() as td:
        path = str(pathlib.Path(td) / "r.json")
        publish("p", "1.0.0", {"a.py": V1}, KEY, path)
        out = publish("p", "2.0.0", {"a.py": V2_BROKEN}, KEY, path)
        assert out["status"] == "refused"
        assert out["layer"] == "regression"
        assert load_registry(path)["p"]["version"] == "1.0.0"


def test_publish_accepts_a_non_regressing_update():
    with tempfile.TemporaryDirectory() as td:
        path = str(pathlib.Path(td) / "r.json")
        publish("p", "1.0.0", {"a.py": V1}, KEY, path)
        out = publish("p", "1.0.1", {"a.py": V1}, KEY, path)
        assert out["status"] == "published"
        assert load_registry(path)["p"]["version"] == "1.0.1"


def test_publish_refuses_on_tampered_registry_entry():
    with tempfile.TemporaryDirectory() as td:
        path = str(pathlib.Path(td) / "r.json")
        publish("p", "1.0.0", {"a.py": V1}, KEY, path)
        reg = load_registry(path)
        reg["p"]["certified"]["a.py"]["proven"].append("fabricated >= 0")
        pathlib.Path(path).write_text(json.dumps(reg))
        out = publish("p", "1.0.1", {"a.py": V1}, KEY, path)
        assert out["status"] == "refused"
        assert out["layer"] == "integrity"


def test_load_registry_missing_file_is_empty():
    assert load_registry("/nonexistent/path/registry.json") == {}


def test_save_and_load_registry_round_trip():
    with tempfile.TemporaryDirectory() as td:
        path = str(pathlib.Path(td) / "r.json")
        save_registry(path, {"x": {"version": "1"}})
        assert load_registry(path) == {"x": {"version": "1"}}
