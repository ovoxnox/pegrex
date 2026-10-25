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
    (nested / "__init__.py").write_text("ignored\n")
    monkeypatch.setattr(mod, "ROOT", tmp_path)
    before = mod.engine_digest()
    (nested / "child.py").write_text("VALUE = 3\n")
    assert mod.engine_digest() != before
    (nested / "child.py").write_text("VALUE = 2\n")
    assert mod.engine_digest() == before


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
