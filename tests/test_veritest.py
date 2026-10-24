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


from pegrex.ir import cond_to_atom, lower_condition
from pegrex.veritest import check_merged, merge_paths, project


def test_dead_var_merging():
    paths = [(frozenset(["(t >= 0)", "(n > 0)"]), "n"),
             (frozenset(["(t <= 5)", "(n > 0)"]), "n")]
    merged = merge_paths(paths, keep=["n"])
    assert len(merged) == 1


def test_live_diff_never_merges():
    paths = [(frozenset(["(n >= 0)"]), "n"), (frozenset(["(n <= 0)"]), "n")]
    assert len(merge_paths(paths, keep=["n"])) == 2


def test_property_proven_over_merged():
    paths = [(frozenset(["(n >= 1)"]), "n"), (frozenset(["(n <= -1)"]), "-n")]
    merged = merge_paths(paths, keep=["n"])
    assert check_merged(merged, "result >= -n")["status"] == "proven"


def test_opaque_never_merges():
    paths = [(frozenset(["(g(n) > 0)"]), "n"), (frozenset(["(h(n) > 0)"]), "n")]
    assert len(merge_paths(paths, keep=["n"])) == 2


def test_constant_comparison_sign_regression():
    # all variables cancel: 0 >= 1 must be FALSE (latent sign bug, m108)
    assert cond_to_atom(lower_condition("(n) >= n + 1")) == "(false)"
    assert cond_to_atom(lower_condition("(n) <= n + 1")) == "(true)"
