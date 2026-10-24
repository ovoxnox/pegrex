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

from pegrex.semantics import contracts_of, semantic_diff, verify_patch

BEFORE = "def classify(n):\n    if n > 0:\n        return 1\n    return -1\n"
FLIP = "def classify(n):\n    if n > 0:\n        return -1\n    return 1\n"
COMMENT = ("def classify(n):\n    # sign class\n    if n > 0:\n"
           "        return 1\n    return -1\n")


def _w(src):
    p = os.path.join(tempfile.mkdtemp(), "m.py")
    open(p, "w").write(src)
    return p


def test_contracts_shape():
    c = contracts_of(_w(BEFORE))
    assert len(c) == 2 and all(isinstance(cs, frozenset) for cs, _ in c)


def test_behavior_change_detected():
    d = semantic_diff(_w(BEFORE), _w(FLIP))
    assert not d["identical"] and len(d["distinguishing"]) == 4


def test_comment_only_identical():
    assert semantic_diff(_w(BEFORE), _w(COMMENT))["identical"]


def test_verify_patch_counterexample():
    out = verify_patch(_w(BEFORE), _w(FLIP))
    assert out["verified"] is False and out["counterexample"]["inputs"].get("n") is not None


def test_verify_patch_equivalent():
    out = verify_patch(_w(BEFORE), _w(COMMENT))
    assert out["verified"] is True and out["counterexample"] is None
