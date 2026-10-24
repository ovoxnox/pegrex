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
from pegrex.strategies import emit_hypothesis, sample_models, strategy, validate

ATOMS = atoms_of(lower_condition("x >= 1 and x <= 10 and y >= x and y <= x + 4"))


def test_samples_satisfy_atoms():
    models = sample_models(ATOMS, n=3)
    assert len(models) >= 2 and not validate(ATOMS, models)


def test_strategy_ranges_from_models():
    st = strategy(ATOMS)
    lo, hi = st["integers"]["x"]
    assert 1 <= lo and hi <= 10


def test_emits_hypothesis():
    src = emit_hypothesis(strategy(ATOMS), "f")
    assert "st.integers" in src and "given" in src


def test_forged_sample_caught():
    bad = validate(ATOMS, [{"x": 50, "y": 0}])
    assert bad and "x" in bad[0]["atom"]


def test_infeasible_path_empty_strategy():
    assert strategy(atoms_of(lower_condition("x < 0 and x > 5"))) == {"one_of": []}
