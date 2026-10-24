"""Unit tests for the m76 typed expression IR."""
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

from pegrex.ir import (CondError, cond_to_atom, linearize, lower_condition,
                       parse_condition, to_sym)
from pegrex.sym import V, const


def test_two_var_comparison():
    assert cond_to_atom(lower_condition("a+1 < b")) == "(1*a - 1*b < -1)"


def test_coefficients():
    assert cond_to_atom(lower_condition("2*i <= n + 1")) == "(2*i - 1*n <= 1)"


def test_compound_and():
    c = lower_condition("x > 0 and y <= x + 2")
    assert c.op == "and" and len(c.args) == 2


def test_word_operators():
    c = lower_condition("x > 0 and not (y < 2)")
    assert c.op == "and"


def test_call_is_opaque():
    assert cond_to_atom(lower_condition("f(x) >= 2")) == "((f(x) >= 2))"


def test_field_is_opaque():
    assert cond_to_atom(lower_condition("obj.f == 3")) == "((obj.f = 3))"


def test_neq_flips_to_disequality():
    assert cond_to_atom(lower_condition("x != 3")) == "(1*x != 3)"


def test_negated_comparison_flips():
    assert cond_to_atom(lower_condition("not (a < b)")) == "(1*a - 1*b >= 0)"


def test_garbage_refuses_loudly():
    for bad in ("a+1 <", "x === 3", "((x < y"):
        with pytest.raises(CondError):
            lower_condition(bad)


def test_linearize_rejects_nonlinear():
    from pegrex.sym import Mul
    assert linearize(Mul(V("x"), V("y"))) is None


def test_old_regex_fragment_preserved():
    # the fast path must still answer the legacy fragment identically
    assert str(lower_condition("n > 0")) == "(n > 0)"
    assert str(lower_condition("n >= 5")) == "(n >= 5)"
