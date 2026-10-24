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


from pegrex.chain import repaired_with_evidence

C = chr(10)
BEFORE = C.join(["def classify(n):", "    if n > 0:", "        return 1",
                 "    return -1", ""])
WRONG = C.join(["def classify(n):", "    return 1", ""])
FIXED = C.join(["def classify(n):", "    if n <= 0:", "        return -1",
                "    return 1", ""])


def test_honest_chain_verified_with_evidence():
    def proposer(fb):
        return WRONG if fb is None else FIXED
    out = repaired_with_evidence(BEFORE, proposer)
    assert out["status"] == "verified" and out["rounds"] == 2
    assert out["evidence"] and all(e["agree"] for e in out["evidence"])


def test_cheat_verifier_caught_by_execution():
    def cheat(a, b, claim="equivalent"):
        return {"verified": True, "counterexample": None}
    out = repaired_with_evidence(BEFORE, lambda fb: WRONG, verifier=cheat)
    assert out["status"] == "refused" and out["layer"] == "execution"
    bad = [e for e in out["evidence"] if not e["agree"]]
    assert bad


def test_runtime_errors_recorded():
    def cheat(a, b, claim="equivalent"):
        return {"verified": True, "counterexample": None}
    broken = C.join(["def classify(n):", "    if n > 0:", "        return 1",
                     "    return undefined_name", ""])
    out = repaired_with_evidence(BEFORE, lambda fb: broken, verifier=cheat)
    errs = [e for e in out.get("evidence", [])
            if str(e["after"]).startswith("error:")]
    assert errs


def test_contract_refusal_precedes_execution():
    out = repaired_with_evidence(BEFORE, lambda fb: WRONG, max_rounds=2)
    assert out["status"] == "refused" and out["layer"] == "contract"
    assert not out["evidence"]
