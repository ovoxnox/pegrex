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


from pegrex.vm import compile_fn, run_fn

C = chr(10)
SRC = C.join(["def classify(n):", "    if n > 0:", "        return 1",
              "    return -1", ""])
SRC2 = C.join(["def clamp(x, lo):", "    if x < lo:", "        y = lo",
               "    else:", "        y = x", "    return y", ""])


def test_vm_matches_python():
    ns = {}
    exec(SRC, ns)
    for n in (1, -3, 0):
        assert run_fn(SRC, n)[0] == ns["classify"](n)


def test_vm_branch_trace():
    _, trace = run_fn(SRC, 1)
    assert len(trace) == 1 and trace[0][1] == "n > 0" and trace[0][2] is True


def test_vm_refuses_for_loops():
    bad = C.join(["def f(n):", "    for i in range(n):", "        n = n + i",
                  "    return n", ""])
    with pytest.raises(Exception):
        compile_fn(bad)


def test_vm_unbound_refused():
    with pytest.raises(RuntimeError):
        run_fn(C.join(["def f(a):", "    return a + b", ""]), 1)
