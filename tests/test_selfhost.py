try:
    import pytest
except ImportError:
    class _Raises:
        def __init__(self, exc): self.exc = exc
        def __enter__(self): return self
        def __exit__(self, t, v, tb):
            assert t is not None and issubclass(t, self.exc), f"expected {self.exc}"
            return True
    class _PytestShim:
        @staticmethod
        def raises(exc): return _Raises(exc)
    pytest = _PytestShim()


import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_selfhost_collect_shape():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "selfhost", ROOT / "tools" / "selfhost.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    d = mod.collect()
    assert d["modules"] > 100 and d["loc"] > 10000, d
    assert d["contract_ok"] + d["contract_unknown"] == d["modules"], d
    assert d["digest"] == mod.engine_digest()
    assert any(r.get("over_budget") for r in d["rows"]), "the engine must find its own hot spots"


def test_selfhost_check_fresh():
    r = subprocess.run([sys.executable, "tools/selfhost.py", "--check"],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_engine_digest_includes_nested_inputs(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "selfhost_digest", ROOT / "tools" / "selfhost.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    engine = tmp_path / "pegrex"
    nested = engine / "nested"
    nested.mkdir(parents=True)
    (engine / "root.py").write_text("VALUE = 1\n")
    (nested / "child.py").write_text("VALUE = 2\n")
    (nested / "__init__.py").write_text("PACKAGE = 1\n")
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    before = mod.engine_digest()
    (nested / "child.py").write_text("VALUE = 3\n")
    assert mod.engine_digest() != before
    (nested / "child.py").write_text("VALUE = 2\n")
    assert mod.engine_digest() == before
    (nested / "__init__.py").write_text("PACKAGE = 2\n")
    assert mod.engine_digest() != before
    assert [p.name for p in mod.engine_files()] == ["__init__.py", "child.py", "root.py"]


def test_selfhost_refusal_reasons_are_bounded_and_checkout_independent(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "selfhost_refusal", ROOT / "tools" / "selfhost.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    reason = mod.refusal_reason(ValueError(str(tmp_path / "engine.py") + "\n" + "x" * 400))
    assert str(tmp_path) not in reason
    assert "<checkout>" in reason
    assert len(reason) <= len("ValueError: ") + 240


def test_selfhost_check_rejects_generated_content_drift(tmp_path, monkeypatch):
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "selfhost_drift", ROOT / "tools" / "selfhost.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    out = tmp_path / "docs" / "SELF.md"
    out.parent.mkdir()
    out.write_text("# SELF.md\n\nengine digest: `same`\nmodules: **1**\n")
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    monkeypatch.setattr(mod, "collect", lambda: {"digest": "same", "modules": 1})
    monkeypatch.setattr(mod, "render", lambda d: out.read_text() + "new row\n")
    monkeypatch.setattr(sys, "argv", ["selfhost.py", "--check"])
    assert mod.main() == 1


def test_selfhost_deterministic_render():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "selfhost", ROOT / "tools" / "selfhost.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    d = mod.collect()
    assert mod.render(d) == mod.render(mod.collect())


def test_twin_build_is_deterministic_and_ignores_bytecode_caches(
        tmp_path, monkeypatch):
    import os
    from pegrex import twin

    for directory, callee in (("z", "z_helper"), ("a", "a_helper")):
        package = tmp_path / directory
        package.mkdir()
        (package / "module.py").write_text(
            f"def duplicate():\n    return {callee}()\n",
            encoding="utf-8",
        )
    cache = tmp_path / "a" / "__pycache__"
    cache.mkdir()
    (cache / "ignored.py").write_text(
        "def cache_only():\n    pass\n", encoding="utf-8")

    expected = twin.build(str(tmp_path))
    real_walk = os.walk

    def reversed_walk(root):
        for path, directories, files in real_walk(root):
            directories.reverse()
            files.reverse()
            yield path, directories, files

    monkeypatch.setattr(twin.os, "walk", reversed_walk)
    assert twin.build(str(tmp_path)) == expected
    assert all("__pycache__" not in path
               for path in expected["files"].values())
