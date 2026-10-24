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


from pegrex.cognitive import cognitive_complexity


def test_simple_zero():
    src = chr(10).join(["def f(n):", "    return n", ""])
    assert cognitive_complexity(src)["total"] == 0


def test_nesting_and_booleans():
    src = chr(10).join(["def f(n):", "    while n > 0:",
                        "        if n > 5 and n < 10:", "            n = n - 1", ""])
    assert cognitive_complexity(src)["total"] == 4


def test_recursion_bonus():
    src = chr(10).join(["def f(n):", "    return f(n - 1) if n > 0 else 0", ""])
    assert cognitive_complexity(src)["total"] == 1


def test_syntax_unknown():
    out = cognitive_complexity("def broken(:" + chr(10))
    assert out["verdict"] == "unknown"


def test_refactor_plans():
    big = chr(10).join(["def f(n):", "    while n > 0:",
                        "        if n > 5 and n < 10:",
                        "            if n % 2 == 0:", "                n = n - 2", ""])
    out = cognitive_complexity(big, budget=2)
    assert out["functions"][0]["refactor_plans"]
