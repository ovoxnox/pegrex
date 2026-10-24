import json
import pathlib
import tempfile

from pegrex.cache import AnalysisCache
from pegrex.bisim import bisimilar
from pegrex.smt import auto_feasible
import pipeline
from pegrex.cfg import CFGBuilder
from pegrex.summaries import render_c

ROOT = pathlib.Path(__file__).parent.parent


def test_cache_roundtrip():
    cache = AnalysisCache(tempfile.mkdtemp())
    assert cache.get("x = 1", ("quality",)) is None
    cache.put("x = 1", ("quality",), {"n": 1})
    assert cache.get("x = 1", ("quality",)) == {"n": 1}
    assert cache.get("x = 2", ("quality",)) is None     # content-addressed


def test_bisimilar_fact_python_c():
    py_src = (ROOT / "specs" / "fact.py").read_text()
    c_src = (ROOT / "specs" / "fact.c").read_text()
    p_parse, p_tags, p_cond = pipeline.python_frontend()
    c_parse, c_tags, c_cond = pipeline.c_frontend()
    a = CFGBuilder(p_tags).build(p_parse(py_src))
    b = CFGBuilder(c_tags).build(c_parse(c_src))
    pr = lambda st: (py_src[st.pos:st.endpos]).replace("return", "").strip()
    cr = lambda st: render_c(st, c_src)
    assert bisimilar(a, b, p_cond(py_src), c_cond(c_src), pr, cr)


def test_auto_feasible_fragment_routing():
    assert auto_feasible(["(n = 0)"]) is True
    assert auto_feasible(["(n < 0)", "(n > 5)"]) is False
    assert auto_feasible(["(n < 0)", "(n < 5)"]) is True   # in-fragment


def test_service_fix_method():
    import subprocess as sp, sys, time
    from pathlib import Path
    proc = sp.Popen([sys.executable, "service.py"], cwd=ROOT,
                    stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, text=True)
    try:
        time.sleep(4)
        req = {"method": "fix", "params": {
            "language": "python",
            "source": "import os\ndef f(c):\n    os.system(c)\n"}}
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        resp = json.loads(proc.stdout.readline())
        assert resp["ok"] and resp["focus"], resp
        assert resp["context_window"] == "finding-local (not whole-file)"
    finally:
        proc.terminate()


def test_repo_bundle(tmp_path=None):
    from tools.repokit import verification_bundle
    b = verification_bundle(str(ROOT / "specs" / "fact.py"))
    assert len(b["paths"]) == 2 and b["smt2"]
