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
from pegrex.vm import compile_fn, run_fn

C = chr(10)
SUM = C.join(["def sum_to(n):", "    i = 1", "    s = 0",
              "    while i <= n:", "        s = s + i", "        i = i + 1",
              "    return s", ""])


def test_vm_loop_matches_python():
    ns = {}
    exec(SUM, ns)
    for n in (1, 5, 10):
        assert run_fn(SUM, n)[0] == ns["sum_to"](n)


def test_termination_ranking():
    assert find_ranking("i <= n", deltas_of(["i=i+1"])) == "n - i + 1"


def test_loop_trace_exit():
    _, trace = run_fn(SUM, 3)
    assert [t[2] for t in trace] == [True] * 3 + [False]


def test_unbounded_loop_refused():
    assert find_ranking("x > 0", deltas_of(["y=1"])) is None
    NOP = C.join(["def f(n):", "    x = n", "    while x > 0:", "        y = 1",
                  "    return x", ""])
    with pytest.raises(RuntimeError):
        run_fn(NOP, 5)


def test_opaque_guard_refused():
    CANT = C.join(["def f(n):", "    while unknown(n):", "        n = n - 1",
                   "    return n", ""])
    with pytest.raises(Exception):
        compile_fn(CANT)
