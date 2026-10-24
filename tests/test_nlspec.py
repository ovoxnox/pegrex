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

from pegrex.nlspec import check, propose

SRC = chr(10).join(["def absval(n):", "    if n >= 0:", "        return n",
                    "    return -n", ""])


def _w():
    p = os.path.join(tempfile.mkdtemp(), "n.py")
    open(p, "w").write(SRC)
    return p


def test_proposer_templates():
    assert propose("the result is non-negative") == ["result >= 0"]
    assert propose("n is positive") == ["n > 0"]
    assert propose("flibbertigibbet frobnicate") == []


def test_true_claim_proven():
    out = check(_w(), nl_text="the result is non-negative")
    assert out[0]["status"] == "proven"


def test_contradicted_dropped():
    out = check(_w(), candidates=["result <= -1"])
    assert out[0]["status"] == "dropped"


def test_undecidable_unknown():
    out = check(_w(), candidates=["n <= 1000000"])
    assert out[0]["status"] == "unknown"


def test_pluggable_candidates():
    out = check(_w(), candidates=["result >= 0", "result <= -1"])
    s = {o["candidate"]: o["status"] for o in out}
    assert s == {"result >= 0": "proven", "result <= -1": "dropped"}
