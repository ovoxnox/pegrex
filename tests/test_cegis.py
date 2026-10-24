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


from pegrex.cegis import repair

BEFORE = chr(10).join(["def classify(n):", "    if n > 0:", "        return 1",
                       "    return -1", ""])
WRONG = chr(10).join(["def classify(n):", "    return 1", ""])
FIXED = chr(10).join(["def classify(n):", "    if n <= 0:", "        return -1",
                      "    return 1", ""])
BROKEN = "def classify(n):\n    return [\n"


def test_cegis_verifies_after_feedback():
    log = []
    def proposer(fb):
        log.append(fb)
        return WRONG if fb is None else FIXED
    out = repair(BEFORE, proposer)
    assert out["verified"] is True and out["rounds"] == 2
    assert log[1]["counterexample"]["inputs"].get("n") is not None


def test_stubborn_proposer_exhausts_budget():
    out = repair(BEFORE, lambda fb: WRONG, max_rounds=3)
    assert out["verified"] is False and out["rounds"] == 3
    assert all(t["status"] == "refused" for t in out["trail"])
    assert all(t["feedback"]["counterexample"] for t in out["trail"])


def test_give_up_honored():
    out = repair(BEFORE, lambda fb: None, max_rounds=3)
    assert out["trail"][0]["status"] == "gave-up"


def test_broken_patch_errors_and_loop_recovers():
    seq = iter([BROKEN, FIXED])
    out = repair(BEFORE, lambda fb: next(seq))
    assert out["trail"][0]["status"] == "error"
    assert out["verified"] is True
