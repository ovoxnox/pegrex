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


def test_idiom_translation_does_not_share_source_between_threads():
    from concurrent.futures import ThreadPoolExecutor

    sources = [
        "def f(n):\n    if n == 0:\n        return 1\n    else:\n        return n\n",
        "def f(value):\n    if value == 0:\n        return 2\n    else:\n        return value\n",
    ]
    def render(source):
        parse, tagspec, make_cond = pipeline.python_frontend()
        body = parse(source)
        rule = IdiomRule("identity", ["if_statement"], "{c}|{t}|{e}",
                         slots={"c": 0, "t": 1, "e": 2})
        return translate(body, [rule], [], src=source)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(render, sources * 8))
    for index, result in enumerate(results):
        variable = "n" if index % 2 == 0 else "value"
        value = "1" if index % 2 == 0 else "2"
        assert result == [("identity", f"{variable} == 0|{value}|{variable}")]
