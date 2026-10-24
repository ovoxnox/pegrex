import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

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

from fractions import Fraction

from pegrex.intervals import Interval, IntervalError, bound_equivalence, \
    error_interval, propagate
from pegrex.mlgraph import MLGraphError, quant_error_bound

S = Fraction(1, 8)


def snap(v):
    return Fraction(round(Fraction(v) / S)) * S


def _net():
    g_f = [
        {"op": "linear", "inputs": ["x"], "weights": [Fraction(26, 100),
         Fraction(12, 100)], "bias": Fraction(13, 100), "out": "h1"},
        {"op": "linear", "inputs": ["x"], "weights": [Fraction(-13, 100),
         Fraction(37, 100)], "bias": Fraction(-6, 100), "out": "h2"},
        {"op": "relu", "inputs": ["h1"], "out": "r1"},
        {"op": "relu", "inputs": ["h2"], "out": "r2"},
        {"op": "linear", "inputs": ["r1", "r2"], "weights": [Fraction(51, 100),
         Fraction(-34, 100)], "bias": Fraction(3, 100), "out": "y"},
    ]
    g_q = [
        {"op": "linear", "inputs": ["x"], "weights": [snap(Fraction(26, 100)),
         snap(Fraction(12, 100))], "bias": snap(Fraction(13, 100)),
         "out": "h1"},
        {"op": "linear", "inputs": ["x"], "weights": [snap(Fraction(-13, 100)),
         snap(Fraction(37, 100))], "bias": snap(Fraction(-6, 100)),
         "out": "h2"},
        {"op": "relu", "inputs": ["h1"], "out": "r1"},
        {"op": "relu", "inputs": ["h2"], "out": "r2"},
        {"op": "linear", "inputs": ["r1", "r2"],
         "weights": [snap(Fraction(51, 100)), snap(Fraction(-34, 100))],
         "bias": snap(Fraction(3, 100)), "out": "y"},
    ]
    return g_f, g_q


def test_arithmetic_exact_and_sound():
    a = Interval(-1, 2)
    b = Interval(Fraction(1, 2), 3)
    assert a + b == Interval(-Fraction(1, 2), 5)
    assert a - b == Interval(-4, Fraction(3, 2))
    assert a * b == Interval(-3, 6)          # four quadrant products
    assert -a == Interval(-2, 1)
    assert abs(Interval(-3, 2)) == Interval(0, 3)
    assert abs(Interval(1, 3)) == Interval(1, 3)
    assert Interval(-3, 2).relu() == Interval(0, 2)
    assert Interval(-3, -1).relu() == Interval(0, 0)
    assert Interval(-2, 5).intersection(Interval(0, 9)) == Interval(0, 5)
    assert Interval(-2, 5).hull(Interval(-9, 0)) == Interval(-9, 5)
    assert Interval(-1, 1).contains_zero
    assert not Interval(1, 2).contains_zero
    assert Interval(-3, 2).max_abs == 3
    assert Interval(1, 2) / Interval(4, 8) == Interval(Fraction(1, 8),
                                                       Fraction(1, 2))


def test_unbounded_sides_roundtrip():
    u = Interval(None, 0)
    assert str(u) == "[-inf, 0]"
    assert (-u).hi is None
    assert (u + Interval(1, 1)) == Interval(None, 1)
    assert (u * Interval(-1, 1)) == Interval(None, None)
    assert u.max_abs is None


def test_division_by_zero_containing_interval_refused():
    with pytest.raises(IntervalError):
        Interval(1, 2) / Interval(-1, 1)
    with pytest.raises(IntervalError):
        Interval(1, 2) / Interval(0, 1)     # touches zero too


def test_propagate_linear_and_relu():
    g = [{"op": "linear", "inputs": ["x"], "weights": [2, -1],
          "bias": Fraction(1, 2), "out": "y"}]
    env = propagate(g, {"x": [(-1, 1), (-1, 1)]})
    # y = 2*x0 - x1 + 1/2 over [-1,1]^2 -> [-5/2, 7/2]
    assert env["y"] == Interval(-Fraction(5, 2), Fraction(7, 2))
    env2 = propagate([{"op": "relu", "inputs": ["y"], "out": "z"}], env)
    assert env2["z"] == Interval(0, Fraction(7, 2))


def test_propagate_unknown_op_names_the_op():
    with pytest.raises(IntervalError):
        propagate([{"op": "conv2d", "inputs": ["x"], "out": "y"}],
                  {"x": (0, 1)})


def test_error_interval_sound_on_grid_and_tighter_than_legacy():
    from pegrex.mlgraph import simulate
    g_f, g_q = _net()
    ranges = {"x": [(-1, 1), (-1, 1)]}
    ei = error_interval(g_f, g_q, ranges)
    max_seen = Fraction(0)
    for i in range(-5, 6):
        for j in range(-5, 6):
            x = [Fraction(i, 5), Fraction(j, 5)]
            err = simulate(g_q, {"x": x})["y"] - simulate(g_f, {"x": x})["y"]
            assert ei.lo <= err <= ei.hi
            max_seen = max(max_seen, abs(err))
    assert max_seen <= ei.max_abs
    legacy = sum(SCALES[n["out"]] / 2 for n in g_q
                 if n["out"] in SCALES) if (SCALES := {"h1": S, "h2": S,
                                                       "y": S}) else 0
    assert ei.max_abs < legacy


def test_bound_equivalence_three_valued():
    g_f, g_q = _net()
    ranges = {"x": [(-1, 1), (-1, 1)]}
    be = bound_equivalence(g_f, g_q, ranges)
    assert be["verdict"] == "unknown" and be["equivalent"] is None
    same = bound_equivalence(g_f, g_f, ranges)
    assert same["verdict"] == "proved" and same["equivalent"] is True
    bad = bound_equivalence(
        g_f, [{"op": "conv2d", "inputs": ["x"], "out": "y"}], ranges)
    assert bad["verdict"] == "refused" and bad["equivalent"] is None
    assert "conv2d" in bad["reason"]


def test_quant_error_bound_delegates_to_intervals():
    _, g_q = _net()
    scales = {"h1": S, "h2": S, "y": S}
    qb = quant_error_bound(g_q, scales)              # default: intervals
    assert 0 < qb <= float(S) * len(scales) / 2 + 1e-9
    leg = quant_error_bound(g_q, scales, method="legacy")
    assert leg == float(S) / 2 * len(scales)         # retired heuristic
    with pytest.raises(MLGraphError):
        quant_error_bound([{"op": "conv2d", "inputs": ["x"], "out": "y"}],
                          {})
