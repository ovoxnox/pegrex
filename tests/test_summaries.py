import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pipeline
from pegrex.cfg import CFGBuilder
from pegrex.summaries import render_lua, render_c, path_summaries

ROOT = pathlib.Path(__file__).parent.parent


def _contracts(lang):
    if lang == "python":
        parse, tagspec, make_cond = pipeline.python_frontend()
        src = (ROOT / "specs" / "fact.py").read_text()
        body = parse(src)
        return path_summaries(
            CFGBuilder(tagspec).build(body), make_cond(src),
            lambda st: (src[st.pos:st.endpos]).replace("return", "").strip())
    parse, tagspec, make_cond = pipeline.c_frontend()
    src = (ROOT / "specs" / "fact.c").read_text()
    body = parse(src)
    return path_summaries(CFGBuilder(tagspec).build(body), make_cond(src),
                          lambda st: render_c(st, src))


EXPECTED = [
    (frozenset({"(n = 0)"}), "1"),
    (frozenset({"(not (n = 0))"}), "n * fact(n - 1)"),
]


def test_lua_contract():
    assert _contracts("python") == EXPECTED


def test_c_contract():
    assert _contracts("c") == EXPECTED


def test_cross_language_contract_equality():
    assert _contracts("python") == _contracts("c")
