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


from pegrex.concolic import flip_and_verify, trace_fn

SRC = chr(10).join(["def classify(n):", "    if n > 0:", "        return 1",
                    "    return -1", ""])
NS = {}
exec(SRC, NS)
CLASSIFY = NS["classify"]

SRC2 = chr(10).join(["def clamp(x, lo):", "    if x < lo:", "        return lo",
                     "    return x", ""])
NS2 = {}
exec(SRC2, NS2)
CLAMP = NS2["clamp"]


def test_trace_collects_branches():
    run = trace_fn(CLASSIFY, 1, source=SRC)
    assert run["branches"] == [(2, "n > 0", True)] and run["opaque_branches"] == 0


def test_flip_solves_and_confirms():
    run = trace_fn(CLASSIFY, 1, source=SRC)
    out = flip_and_verify(CLASSIFY, run, 0, source=SRC)
    assert out["status"] == "ok" and out["inputs"]["n"] <= 0
    assert out["rerun"]["branches"][0][2] is False


def test_multi_param_signature_order():
    run = trace_fn(CLAMP, 5, 2, source=SRC2)
    out = flip_and_verify(CLAMP, run, 0, source=SRC2)
    assert out["status"] == "ok" and out["inputs"]["x"] < out["inputs"]["lo"]
    assert out["rerun"]["result"] == out["inputs"]["lo"]


def test_infeasible_flip_with_prefix():
    nested = chr(10).join(["def f(n):", "    if n > 0:", "        if n < 0:",
                           "            return 1", "    return 0", ""])
    nsn = {}
    exec(nested, nsn)
    run = trace_fn(nsn["f"], 1, source=nested)
    out = flip_and_verify(nsn["f"], run, 1, source=nested)
    assert out["status"] == "infeasible-flip"


def test_opaque_branch_refused():
    src4 = chr(10).join(["def g(n):", "    if unknown_pred(n):",
                         "        return 1", "    return 0", ""])
    ns4 = {}
    exec(src4, ns4)
    ns4["unknown_pred"] = lambda n: n % 2 == 0
    run = trace_fn(ns4["g"], 2, source=src4)
    assert run["opaque_branches"] == 1
    assert flip_and_verify(ns4["g"], run, 0, source=src4)["status"] == "opaque-branch"
