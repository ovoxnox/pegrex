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


from pegrex.eggx import (SOUND, congruence_close, const_analysis,
                            saturate_validated, validate_rule)
from pegrex.egraphs import EGraph


def test_commutativity_saturation():
    g = EGraph()
    a = g.add("add", (g.add("lit", (), 1), g.add("lit", (), 2)))
    b = g.add("add", (g.add("lit", (), 2), g.add("lit", (), 1)))
    saturate_validated(g, [((("add", 0, 1), ("add", 1, 0)), SOUND)])
    assert g.find(a) == g.find(b)


def test_congruence_closure():
    g = EGraph()
    x1 = g.add("add", (g.add("lit", (), 1), g.add("lit", (), 2)))
    x2 = g.add("add", (g.add("lit", (), 2), g.add("lit", (), 1)))
    saturate_validated(g, [((("add", 0, 1), ("add", 1, 0)), SOUND)])
    f1, f2 = g.add("f", (x1,)), g.add("f", (x2,))
    assert g.find(f1) != g.find(f2)
    congruence_close(g)
    assert g.find(f1) == g.find(f2)


def test_const_analysis_folds():
    g = EGraph()
    t = g.add("mul", (g.add("add", (g.add("lit", (), 1), g.add("lit", (), 2))),
                      g.add("lit", (), 4)))
    assert const_analysis(g)[g.find(t)] == 12


def test_oracle_refuses_unsound():
    v = validate_rule(lambda x: x - x, lambda x: 1)
    assert not v["sound"] and v["counterexamples"]


def test_refused_rule_never_applies():
    g = EGraph()
    s = g.add("sub", (g.add("lit", (), 5), g.add("lit", (), 5)))
    out = saturate_validated(g, [((("sub", 0, 0), ("lit", 1)),
                                  validate_rule(lambda x: x - x, lambda x: 1))])
    assert len(out["refused"]) == 1
    assert const_analysis(g).get(g.find(s)) == 0
