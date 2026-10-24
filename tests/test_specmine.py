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


import os
import tempfile

from pegrex.specmine import mine

SRC = chr(10).join(["def absval(n):", "    if n >= 0:", "        return n",
                    "    return -n", ""])


def _w(src):
    p = os.path.join(tempfile.mkdtemp(), "s.py")
    open(p, "w").write(src)
    return p


def test_mines_semantic_spec_proven():
    out = mine(_w(SRC))
    assert "result >= 0" in out["proven"]
    assert "result >= n" in out["proven"]


def test_contradicted_dropped():
    out = mine(_w(SRC))
    assert "result <= 0" in out["dropped"]


def test_classification_disjoint():
    out = mine(_w(SRC))
    assert not (set(out["proven"]) & set(out["dropped"]))
    assert not (set(out["proven"]) & set(out["likely"]))


def test_keys():
    out = mine(_w(SRC))
    assert set(out) == {"proven", "likely", "dropped"}
