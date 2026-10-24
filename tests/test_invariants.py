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


from pegrex.invariants import infer_invariants
from pegrex.ir import lower_condition
from pegrex.linsolve import atoms_of

GUARD = "i <= n"
DELTAS = {"i": 1}
INIT = atoms_of(lower_condition("i >= 1 and i <= 1 and n >= 1 and s >= 0 and s <= 0"))


def test_defended_invariants():
    inv = infer_invariants(GUARD, DELTAS, INIT)["invariants"]
    assert "i >= 1" in inv and "i <= n + 1" in inv


def test_inductively_broken_dropped():
    inv = infer_invariants(GUARD, DELTAS, INIT)["invariants"]
    assert "i <= n" not in inv and "i <= n - 1" not in inv


def test_initiation_failures_dropped():
    dropped = infer_invariants(GUARD, DELTAS, INIT)["dropped_at_initiation"]
    assert "i <= 0" in dropped and "i >= n - 1" in dropped


def test_nonstepped_var_no_step_claims():
    inv = infer_invariants(GUARD, DELTAS, INIT)["invariants"]
    assert "s <= 0" not in inv
