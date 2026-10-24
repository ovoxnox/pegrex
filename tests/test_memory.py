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


from pegrex.memory import Memory, Pointer


def _m():
    m = Memory()
    return m, m.alloc("buf", 4)


def test_safe_access():
    m, buf = _m()
    assert m.access(buf, "i", ["i >= 0", "i <= 3"])["status"] == "safe"


def test_provably_oob_high_and_low():
    m, buf = _m()
    assert m.access(buf, "i", ["i >= 4"])["status"] == "provably-oob"
    assert m.access(buf, "j", ["j <= -1"])["status"] == "provably-oob"


def test_maybe_oob_honest():
    m, buf = _m()
    r = m.access(buf, "i", ["i >= 2"])
    assert r["status"] == "maybe-oob" and r["low_proven"]


def test_alias_judgments():
    m, buf = _m()
    assert m.alias(Pointer(buf, "i"), Pointer(buf, "i"), ["i >= 0"])["status"] == "must-alias"
    other = m.alloc("other", 4)
    assert m.alias(Pointer(buf, "i"), Pointer(other, "i"))["status"] == "no-alias"
    assert m.alias(Pointer(buf, "i"), Pointer(buf, "k"), ["i >= 0", "k >= 0"])["status"] == "may-alias"


def test_proven_distinct_offsets():
    m, buf = _m()
    r = m.alias(Pointer(buf, "i"), Pointer(buf, "i + 1"), ["i >= 0"])
    assert r["status"] == "no-alias"


def test_safe_never_claimed_without_proof():
    m, buf = _m()
    assert m.access(buf, "i", ["i >= 0"])["status"] != "safe"
