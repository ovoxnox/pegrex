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

from pegrex.rank import deltas_of, find_ranking


def test_ascending_loop():
    assert find_ranking("i <= n", deltas_of(["i=i+1"])) == "n - i + 1"


def test_strict_guard():
    assert find_ranking("i < n", {"i": 1}) == "n - i + 1"


def test_descending_loop():
    r = find_ranking("i >= 1", {"i": -1})
    assert r is not None and r.startswith("i -")


def test_no_progress_refused():
    assert find_ranking("i < n", {"i": 0}) is None


def test_unbounded_counter_refused():
    assert find_ranking("x > 0", {"i": 1}) is None


def test_while_true_refused():
    assert find_ranking("true", {"i": 1}) is None
