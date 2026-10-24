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


from pegrex.eggx import (SOUND, congruence_close, saturate_vars,
                         validate_rule)
from pegrex.egraphs import EGraph

COMMUT = (("add", "?a", "?b"), ("add", "?b", "?a"))
ASSOC = (("add", ("add", "?a", "?b"), "?c"),
         ("add", "?a", ("add", "?b", "?c")))


def test_node_var_commutativity():
    g = EGraph()
    x = g.add("mul", (g.add("lit", (), 2), g.add("var", (), "a")))
    y = g.add("var", (), "b")
    n1, n2 = g.add("add", (x, y)), g.add("add", (y, x))
    saturate_vars(g, [(COMMUT, SOUND)])
    assert g.find(n1) == g.find(n2)


def test_associativity():
    g = EGraph()
    a1 = g.add("add", (g.add("lit", (), 1), g.add("lit", (), 2)))
    l = g.add("add", (a1, g.add("lit", (), 3)))
    r_ = g.add("add", (g.add("lit", (), 1),
                       g.add("add", (g.add("lit", (), 2), g.add("lit", (), 3)))))
    saturate_vars(g, [(ASSOC, SOUND)])
    assert g.find(l) == g.find(r_)


def test_fire_once_terminates():
    g = EGraph()
    p, q = g.add("var", (), "p"), g.add("var", (), "q")
    g.add("add", (p, q))
    out = saturate_vars(g, [(COMMUT, SOUND), (ASSOC, SOUND)])
    assert out["admitted"] == 2


def test_unsound_var_rule_refused():
    bad = validate_rule(lambda x: x - x, lambda x: 1)
    g = EGraph()
    u = g.add("sub", (g.add("var", (), "u"), g.add("var", (), "u")))
    out = saturate_vars(g, [((("sub", "?z", "?z"), ("lit", 1)), bad)])
    assert out["admitted"] == 0 and len(out["refused"]) == 1


def test_nonmatching_pattern_noop():
    g = EGraph()
    m = g.add("mul", (g.add("lit", (), 1), g.add("lit", (), 2)))
    before = g.find(m)
    saturate_vars(g, [((("add", "?a", "?b"), ("add", "?b", "?a")), SOUND)])
    assert g.find(m) == before and len(g.nodes) == 3
