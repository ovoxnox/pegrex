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


from pegrex.octagon import Octagon, widen


def test_precision_over_intervals():
    o = Octagon(["x + y <= 4", "x - y <= 2"]).close()
    assert o.upper("x") == 3
    assert o.upper("y") is None          # y genuinely unbounded


def test_entailment():
    o = Octagon(["x + y <= 4", "x - y <= 2"]).close()
    assert o.entails("x <= 3") and not o.entails("x <= 2")


def test_unary_bounds():
    o = Octagon(["x <= 5", "-x <= 1"]).close()
    assert o.lower("x") == -1 and o.upper("x") == 5


def test_negative_cycle_infeasible():
    assert not Octagon(["x + y <= 0", "-x - y <= -1"]).close().feasible()
    assert Octagon(["x + y <= 0", "-x - y <= 0"]).close().feasible()


def test_widening_sound():
    a = Octagon(["x <= 5", "-x <= 1"])
    w_same = widen(a, a)
    assert w_same.entails("x <= 5")
    assert widen(a, Octagon(["x <= 6", "-x <= 0"])).upper("x") is None


def test_fragment_refusal():
    try:
        Octagon(["x * y <= 4"])
        assert False
    except ValueError:
        pass
