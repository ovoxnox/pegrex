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


from pegrex.ir import lower_condition
from pegrex.linsolve import atoms_of
from pegrex.pdr import check_property

GUARD = "i <= n"
DELTAS = {"i": 1}
INIT = atoms_of(lower_condition("i >= 1 and i <= 1 and n >= 1"))


def test_proven_with_certificate():
    r = check_property(GUARD, DELTAS, INIT, "i >= 1")
    assert r["status"] == "proven" and "i >= 1" in r["certificate"]["invariants"]


def test_violated_with_witness():
    r = check_property(GUARD, DELTAS, INIT, "i <= 0")
    assert r["status"] == "violated" and r["witness"]["i"] == 1


def test_unknown_honest():
    r = check_property(GUARD, DELTAS, INIT, "i <= 3")
    assert r["status"] == "unknown"
