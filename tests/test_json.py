import pathlib

from pegrex import compile_grammar, peg

GRAMMAR = (pathlib.Path(__file__).parent.parent / "examples" / "json.gram").read_text()
SRC = '[{"string":"some\\ntext", "boolean":true, "number":-1.5e+2, "null":null}]'


def test_json_full():
    start, rules = compile_grammar(GRAMMAR)
    ast, err, _ = peg.run(start, SRC, rules)
    assert err is None and ast.tag == "Array"
    obj = ast.children[0]
    assert obj.tag == "Object" and len(obj.children) == 4
    assert obj.children[0].children[1] == "some\ntext"
    assert obj.children[1].children[1] is True
    assert obj.children[2].children[1] == -150.0
    assert len(obj.children[3].children) == 2
    assert obj.children[3].children[1] is None


def test_error_label():
    start, rules = compile_grammar(GRAMMAR)
    ast, err, pos = peg.run(start, '[{"a":', rules)
    assert ast is None and err == "Expected_Value"
    ast, err, pos = peg.run(start, '{"a":1} x', rules)
    assert ast is None and err == "UnexpectedSyntax"


def test_calcline():
    from pegrex import calcline
    assert calcline("ab\ncd", 4) == (2, 2, "cd")
