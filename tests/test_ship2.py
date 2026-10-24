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


import os
import tempfile
import time

from pegrex import compliance, mlgraph, probpath, slsa, twin
from pegrex import api, vapi

C = chr(10)


def test_compliance_gdpr_finding():
    src = C.join(["# pii: email", "# sink: send_grid needs consent",
                  "def signup():", "    user_input = email",
                  "    send_grid(user_input)", "    return 1"])
    f = compliance.audit_gdpr(src)
    assert f and f[0]["kind"] == "gdpr-no-consent"


def test_mlgraph_equivalence():
    g = [{"op": "linear", "inputs": ["x"], "weights": [2.0, 0.0],
          "bias": 0.5, "out": "y"}]
    r = mlgraph.check_equivalence(g, g, [{"x": [1.0, -1.0]}], {"y": 0.01}, 0.05)
    assert r["verdict"] == "proved"
    r2 = mlgraph.check_equivalence(g, g, [{"x": [1.0, -1.0]}], {"y": 1.0}, 0.05)
    assert r2["verdict"] == "refuted"


def test_twin_reach_and_ask():
    d = tempfile.mkdtemp()
    open(os.path.join(d, "s.py"), "w").write(
        C.join(["def handle(n):", "    if n > 0:", "        db_execute(n)",
                "    return 1"]))
    t = twin.build(d)
    assert twin.reach(t, "db_execute") == ["handle"]
    assert twin.ask(t, "which functions can reach db_execute?")["functions"] == ["handle"]


def test_probpath_frequencies():
    src = C.join(["def classify(n):", "    if n > 0:", "        return 1",
                  "    return -1", ""])
    p = os.path.join(tempfile.mkdtemp(), "c.py")
    open(p, "w").write(src)
    contracts = api.contracts(p)
    from pegrex.refine import _norm_constraint
    else_atoms = set()
    for cs, _ in contracts:
        if any("not" in str(c) for c in cs):
            else_atoms = set(_norm_constraint(str(c)) for c in cs)
    traces = [set(["(n > 0)"])] * 3 + [else_atoms]
    f = probpath.fit(contracts, traces)
    assert f["total_runs"] == 4
    assert any(r["count"] == 3 for r in f["paths"])


def test_slsa_attestation():
    d = tempfile.mkdtemp()
    m = os.path.join(d, "m.py")
    open(m, "w").write(C.join(["def f():", "    return 1", ""]))
    a = slsa.attest("b", "cmd", {}, [m], "k")
    assert slsa.verify(a, "k")["ok"] is True
    open(m, "w").write(C.join(["def f():", "    return 2", ""]))
    assert slsa.verify(a, "k")["ok"] is False


def test_vapi_deadline_unknown():
    a = os.path.join(tempfile.mkdtemp(), "a.py")
    open(a, "w").write(C.join(["def f(n):", "    if n > 0:", "        return 1",
                               "    return -1", ""]))
    out = vapi.verify_or_refuse(a, a, deadline_ms=5000)
    assert out["verdict"] == "proved"
    def hang(x, y):
        time.sleep(30)
        return {"verified": True}
    out2 = vapi.verify_or_refuse(a, a, deadline_ms=200, verifier=hang)
    assert out2["verdict"] == "unknown" and out2["completed"] is False
