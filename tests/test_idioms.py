import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pipeline
from pegrex.idioms import IdiomRule, translate, guard_holds
from pegrex.cfg import CFGBuilder


SRC = ""


def _setup():
    parse, tagspec, make_cond = pipeline.python_frontend()
    src = (pathlib.Path(__file__).parent.parent / "specs" / "fact.py").read_text()
    body = parse(src)
    global SRC
    SRC = src
    cons = pipeline.path_constraints(CFGBuilder(tagspec).build(body),
                                     make_cond(src), 1)
    return body, cons


def test_idiom_fires_with_guard():
    body, cons = _setup()
    rule = IdiomRule("ternary", ["if_statement"], "return {c} ? {t} : {e};",
                     path_guard="(= n 0)", slots={"c": 0, "t": 1, "e": 2})
    out = translate(body, [rule], cons, src=SRC)
    assert out == [("ternary", "return n == 0 ? 1 : n * fact(n - 1);")], out


def test_idiom_blocked_by_guard():
    body, cons = _setup()
    rule = IdiomRule("never", ["if_statement"], "X", path_guard="(= n 999)")
    assert translate(body, [rule], cons) == []


def test_idiom_no_guard_always_fires():
    body, cons = _setup()
    rule = IdiomRule("always", ["if_statement"], "Y", slots={"c": 0, "t": 1, "e": 2})
    assert len(translate(body, [rule], cons)) == 1
