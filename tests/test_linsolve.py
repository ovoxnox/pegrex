"""Unit tests for the m77 Fourier-Motzkin solver."""
try:
    import pytest
except ImportError:                       # dependency-free shim mode
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
from pegrex.linsolve import LinearBackend, atoms_of, parse_atom, LinearError

b = LinearBackend()


def _learn(cond):
    return b.learn(atoms_of(lower_condition(cond)))


def test_model_coupled_vars():
    assert _learn("x >= 2 and y >= x + 1").model() == {"x": 2, "y": 3}


def test_cyclic_infeasible():
    assert not _learn("x < y and y < z and z < x").feasible()


def test_gt_normalization():
    assert not _learn("n < 0 and n > 5").feasible()


def test_disequality_repair():
    assert _learn("x != 3 and x >= 3").model() == {"x": 4}


def test_equality_system():
    assert _learn("x + y = 4 and x - y = 2").model() == {"x": 3, "y": 1}


def test_entailment_true():
    m = _learn("x >= 2 and y <= x + 1")
    assert b.entails(m, lower_condition("y <= x + 5")) is True


def test_entailment_false():
    m = _learn("x >= 2 and y <= x + 1")
    assert b.entails(m, lower_condition("y <= x")) is False


def test_opaque_guard_refused():
    m = _learn("x >= 2 and y <= x + 1")
    assert b.entails(m, lower_condition("f(x) > 1")) is False


def test_nonlinear_atom_raises():
    with pytest.raises(LinearError):
        parse_atom("(x*y < 4)")


def test_equality_guard_conjuncts_checked_individually():
    # regression: ~(A & B) is a disjunction; negating pieces and conjoining
    # them made 'i - k = 0' wrongly entailed under unrelated constraints
    m = _learn("i >= 0 and k >= 0")
    assert b.entails(m, lower_condition("i - k = 0")) is False
    m2 = _learn("i >= 0 and k >= 0 and i - k = 0")
    assert b.entails(m2, lower_condition("i - k = 0")) is True
