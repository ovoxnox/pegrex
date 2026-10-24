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


"""Unit tests for the m130-m138 modules (certs cover them; these cover
the seams between sessions)."""
import os
import tempfile

from pegrex import api, facade


def test_facade_surface():
    for name in ("verify_patch", "modernize", "cognitive_complexity",
                 "bounty_run", "audit_circuit", "verify_or_refuse",
                 "check_plan", "PROVED", "UNKNOWN"):
        assert hasattr(facade, name), name


def test_graph_writers_query():
    from pegrex.graph import build_graph, query_writers
    g = build_graph(
        twin_edges=[("reaches", "api.handler", "db.execute"),
                    ("reaches", "cron.job", "db.execute"),
                    ("auth", "api.handler", "db.execute")])
    out = query_writers(g, "db.execute")
    assert out["unauthorized_writers"] == ["cron.job"]
    assert query_writers(g, "nope")["verdict"] == "unknown"


def test_autopwn_layers():
    from pegrex.autopwn import autopwn
    V = chr(10).join(["def q(x):", "    if x > 5 and x > 0:",
                      "        db_execute(x)", "    return 1"])
    F = chr(10).join(["def q(x):", "    if x <= 5:", "        return 1"])
    out = autopwn(V, "db_execute", lambda fb: F)
    assert out["status"] in ("poc-fixed", "refused", "unknown")
    out2 = autopwn(V, "db_execute", lambda fb: F,
                   policy=[{"effect": "deny", "tool": "shell", "args": "*pytest*"}])
    assert out2["status"] == "refused" and out2["layer"] == "policy"


def test_priorverify_coverage():
    from pegrex.priorverify import verify_under_budget
    src = chr(10).join(["def f(n):", "    if n > 0:", "        return 1",
                        "    return -1", ""])
    p = os.path.join(tempfile.mkdtemp(), "f.py")
    open(p, "w").write(src)
    cs = api.contracts(p)
    out = verify_under_budget(cs, [set(["(n > 0)"])] * 2, lambda a: "proved", 1000)
    assert out["total_runs"] == 2


def test_py2cobol_round_trip():
    from pegrex.py2cobol import round_trip
    p = os.path.join(tempfile.mkdtemp(), "a.py")
    open(p, "w").write(chr(10).join(["def absval(n):", "    if n >= 0:",
                                     "        return n", "    return -n", ""]))
    assert round_trip(p)["identity"] is True


def test_legalci_base_dates():
    from pegrex.legal import parse_clauses
    from pegrex.legalci import report_clauses
    from datetime import date
    clauses = parse_clauses("Buyer shall pay within 30 days.")
    for c in clauses:
        c["base_date"] = "2026-06-01"
    rep = report_clauses(clauses, today=date.fromisoformat("2026-07-15"))
    assert rep["failures"] == 1, rep


def test_antihalluc_refusal():
    from pegrex.antihalluc import compile_nl
    p = os.path.join(tempfile.mkdtemp(), "a.py")
    open(p, "w").write(chr(10).join(["def absval(n):", "    if n >= 0:",
                                     "        return n", "    return -n", ""]))
    ok = compile_nl("the result is non-negative", p)
    assert ok["verdict"] == "proved" and ok["code"]
    bad = compile_nl("the result is non-positive", p)
    assert bad["verdict"] == "refuted" and bad["code"] is None


def test_orgtwin_teams():
    from pegrex.orgtwin import org_report, who_is_at_risk
    d = tempfile.mkdtemp()
    open(os.path.join(d, "s.py"), "w").write(chr(10).join([
        "# owner: team-a", "def f(n):", "    return n"]))
    rep = org_report(d, budget=1)
    assert "team-a" in rep["teams"]
