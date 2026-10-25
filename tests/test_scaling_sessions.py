"""Speed/scaling contracts: shared parses, content keys, and invalidation."""
from pegrex import sessions
from pegrex.cache import AnalysisCache, IncrementalSummaryCache
from pegrex.sessions import AnalysisSession

SOURCE = "def f(x):\n    if x > 0:\n        return x\n    return eval(x)\n"


def test_analysis_cache_identity_is_content_version_and_configuration(tmp_path):
    cache = AnalysisCache(tmp_path)
    analyzers = ("contracts", "parse")
    cache.put(SOURCE, analyzers, {"ok": True}, version="parser-1/analyzer-2",
              configuration={"mode": "strict"})
    assert cache.get(SOURCE, analyzers, version="parser-1/analyzer-2",
                     configuration={"mode": "strict"}) == {"ok": True}
    assert cache.get(SOURCE + "\n", analyzers, version="parser-1/analyzer-2",
                     configuration={"mode": "strict"}) is None
    assert cache.get(SOURCE, analyzers, version="parser-2/analyzer-2",
                     configuration={"mode": "strict"}) is None
    assert cache.get(SOURCE, analyzers, version="parser-1/analyzer-2",
                     configuration={"mode": "lenient"}) is None
    assert len(list(tmp_path.glob("*.json"))) == 1


def test_one_normalized_tree_feeds_all_session_consumers(monkeypatch):
    calls = []
    real_parse = sessions.parse_source

    def counted(language, source):
        calls.append((language, source))
        return real_parse(language, source)

    monkeypatch.setattr(sessions, "parse_source", counted)
    session = AnalysisSession(SOURCE)
    tree = session.tree
    assert session.tree is tree
    assert session.call_graph.functions["f"]["calls"] == {"eval"}
    assert session.contracts()
    assert session.complexity["verdict"] == "ok"
    assert session.security
    assert len(calls) == 1


def test_persistent_tree_is_addressed_by_content_not_path(tmp_path, monkeypatch):
    cache = AnalysisCache(tmp_path / "cache")
    first = AnalysisSession(SOURCE, path="first.py", cache=cache)
    assert first.tree.tag == "module"
    monkeypatch.setattr(sessions, "parse_source",
                        lambda *_: (_ for _ in ()).throw(AssertionError("unexpected parse")))
    second = AnalysisSession(SOURCE, path="renamed.py", cache=cache)
    assert second.tree.tag == "module"
    assert second.contracts() == first.contracts()
    changed = AnalysisSession(SOURCE + "\n", path="first.py", cache=cache)
    assert changed.digest != first.digest


def test_changed_callee_invalidates_transitive_call_summaries():
    cache = IncrementalSummaryCache()
    cache.update("caller.py", "caller", dependencies=["callee.py"])
    cache.update("callee.py", "callee", dependencies=["base.py"])
    cache.update("base.py", "base")
    for name in ("caller.py", "callee.py", "base.py"):
        cache.put(name, {"summary": name})
    assert cache.update("base.py", "base changed") == {
        "base.py", "callee.py", "caller.py"}
    assert all(cache.get(name) is None
               for name in ("caller.py", "callee.py", "base.py"))
    cache.put("callee.py", {"summary": "new"})
    assert cache.get("callee.py") == {"summary": "new"}


def test_per_file_deadline_is_explicit_unknown():
    report = AnalysisSession(SOURCE, timeout_ms=0).analyze(("contracts",))
    result = report["results"]["contracts"]
    assert result["status"] == "unknown"
    assert result["resource"] == "per-file-timeout"
