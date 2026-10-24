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


def test_selfhost_deterministic_render():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "selfhost", ROOT / "tools" / "selfhost.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    d = mod.collect()
    assert mod.render(d) == mod.render(mod.collect())
