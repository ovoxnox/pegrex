"""Resource limits are explicit UNKNOWNs, never truncated proofs."""
from pegrex.cfg import CFG
from pegrex.linsolve import LinearBackend
from pegrex.octagon import Octagon, widen
from pegrex.paths import PathEnumerator, PathExplosion
from pegrex.sessions import AnalysisSession
from pegrex.sym import Ge, V

import pytest


def branching_cfg():
    cfg = CFG()
    cfg.add_block(term="branch")
    cfg.add_block(term="ret")
    cfg.add_block(term="ret")
    cfg.add_edge(0, 2, kind="else")
    cfg.add_edge(0, 1, kind="then")
    return cfg


def test_path_cap_returns_unknown_and_no_partial_paths():
    result = PathEnumerator(branching_cfg()).enumerate_bounded(max_paths=1)
    assert result.verdict == "unknown"
    assert result.complete is False
    assert result.paths == []
    assert "path count cap 1 exceeded" in result.unknowns
    with pytest.raises(PathExplosion):
        PathEnumerator(branching_cfg(), max_paths=1).enumerate()


def test_path_traversal_is_deterministic_and_complete_without_cap():
    result = PathEnumerator(branching_cfg()).enumerate_bounded(max_paths=2)
    assert result.complete is True
    assert result.paths == [[0, 1], [0, 2]]
    assert result.verdict == "ok"


def test_path_timeout_is_unknown():
    result = PathEnumerator(branching_cfg()).enumerate_bounded(timeout_ms=0)
    assert result.verdict == "unknown"
    assert result.paths == []
    assert "exceeded 0ms" in result.unknowns[0]


def test_contract_path_cap_is_observable_resource_unknown():
    source = "def f(x):\n    if x > 0:\n        return 1\n    return 0\n"
    report = AnalysisSession(source, max_paths=1).analyze(("contracts",))
    result = report["results"]["contracts"]
    assert result["status"] == "unknown"
    assert result["resource"] == "path-count-cap"
    assert "data" not in result


def test_solver_query_budget_has_status_and_legacy_fails_closed():
    backend = LinearBackend(max_queries=0)
    model = backend.learn(["(x >= 0)"])
    result = backend.entails_with_status(model, Ge(V("x"), 0))
    assert result["status"] == "unknown"
    assert "query budget 0 exceeded" in result["reason"]
    assert backend.entails(model, Ge(V("x"), 0)) is False


def test_solver_deadline_is_unknown():
    backend = LinearBackend(timeout_ms=0)
    model = backend.learn(["(x >= 0)"])
    assert backend.entails_with_status(model, Ge(V("x"), 0))["status"] == "unknown"


def test_widening_output_order_is_deterministic():
    a, b = Octagon(), Octagon()
    a.edges = {("z-", "z+"): 4, ("x-", "x+"): 2, ("y-", "y+"): 6}
    b.edges = dict(a.edges)
    assert list(widen(a, b).edges) == sorted(widen(a, b).edges)
