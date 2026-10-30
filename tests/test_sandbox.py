import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

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

import pegrex.sandbox as sandbox
from pegrex.sandbox import SandboxError, run_cegis_candidate, \
    run_python_isolated
from pegrex.chain import repaired_with_evidence

C = chr(10)
BEFORE = C.join(["def classify(n):", "    if n > 0:", "        return 1",
                 "    return -1", ""])
FIXED = C.join(["def classify(n):", "    if n <= 0:", "        return -1",
                "    return 1", ""])


def test_benign_roundtrip():
    r = run_python_isolated("def add(a, b):\n    return a + b\n", "add",
                            [2, 3], timeout=5.0)
    assert r["ok"] is True and r["result"] == 5
    assert r["isolation"]["environment_cleared"] is True
    assert r["isolation"]["network_isolated"] is False


def test_non_json_result_uses_repr():
    r = run_python_isolated("def f():\n    return {1, 2}\n", "f", [],
                            timeout=5.0)
    assert r["ok"] is True and r["result"] == "{1, 2}"


def test_infinite_loop_refused_quickly():
    t0 = time.time()
    r = run_python_isolated("def loop(n):\n    while True:\n        pass\n",
                            "loop", [1], timeout=1.5)
    wall = time.time() - t0
    assert r["ok"] is False and r["kind"] == "timeout"
    assert wall < 8


def test_crashing_candidate_reports_stderr():
    r = run_python_isolated("def boom(n):\n    raise ValueError('x')\n",
                            "boom", [1], timeout=5.0)
    assert r["ok"] is False and r["kind"] == "crash"
    assert "ValueError" in r["error"]


def test_memory_bomb_refused():
    r = run_python_isolated(
        "def big(n):\n    return [0] * (256 * 1024 * 1024)\n", "big", [1],
        timeout=10.0, mem_mb=64)
    assert r["ok"] is False


def test_run_cegis_candidate_per_input_verdicts():
    out = run_cegis_candidate(FIXED, BEFORE, [{"n": 3}, {"n": -2}], None,
                              timeout=5.0)
    assert out["verified"] is True and len(out["evidence"]) == 2
    assert all(e["agree"] and e["sandbox_ok"] for e in out["evidence"])
    bad = run_cegis_candidate("def classify(n):\n    return 1\n", BEFORE,
                              [{"n": -2}], None, timeout=5.0)
    assert bad["verified"] is False and bad["disagreements"] == 1


def test_chain_with_sandbox_end_to_end():
    out = repaired_with_evidence(BEFORE, lambda fb: FIXED, use_sandbox=True,
                                 n_samples=2)
    assert out["status"] == "verified"
    assert out["evidence"] and all(e["agree"] for e in out["evidence"])


def test_chain_refuses_when_isolation_unavailable(monkeypatch=None):
    orig = sandbox.sandbox_available
    sandbox.sandbox_available = lambda: False
    try:
        with pytest.raises(SandboxError):
            repaired_with_evidence(BEFORE, lambda fb: FIXED, use_sandbox=True)
    finally:
        sandbox.sandbox_available = orig


def test_isolated_concolic_traces_source_in_child():
    from pegrex.sandbox import run_concolic_isolated
    source = "def classify(x):\n    if x > 0:\n        return 1\n    return 0\n"
    result = run_concolic_isolated(source, "classify", [2], timeout=10, mem_mb=512)
    assert result["status"] == "ok", result
    assert result["result"] == 1
    assert result["branches"] == [[2, "x > 0", True]]
    assert result["execution"]["process_isolated"] is True
    assert result["execution"]["network_isolation"] is False


def test_isolated_concolic_times_out_instead_of_hanging_parent():
    from pegrex.sandbox import run_concolic_isolated
    source = "def loop(x):\n    while True:\n        pass\n"
    result = run_concolic_isolated(source, "loop", [1], timeout=1, mem_mb=512)
    assert result["status"] == "unknown"
    assert result["reason"] in {"worker-timeout", "worker-invalid-output",
                                 "worker-execution-failed"}
