import pathlib

import pegrex
from pegrex import compile_grammar, peg

C11_GRAMMAR = (pathlib.Path(__file__).parent.parent / "examples" / "c11.gram").read_text()

FACT_C = """int fact(int n) {
  if (n == 0) {
    return 1;
  } else {
    return n * fact(n - 1);
  }
}
"""

TYPEDEF_SRC = "typedef int myint; myint x = 3;"


def make_defs():
    typedefs = set()

    def is_typedef(s, pos, node):
        return node.children[0] in typedefs

    def set_typedef(s, pos, *caps):
        node = next((c for c in caps if isinstance(c, pegrex.Node)), None)
        d = node
        while d is not None and d.tag != "identifier":
            kids = [k for k in getattr(d, "children", [])
                    if isinstance(k, pegrex.Node)]
            d = kids[0] if kids else None
        if d is not None:
            typedefs.add(d.children[0])
        return True

    return {"is_typedef": is_typedef, "set_typedef": set_typedef}, typedefs


def find(node, tag):
    if isinstance(node, list):
        for item in node:
            r = find(item, tag)
            if r is not None:
                return r
        return None
    if getattr(node, "tag", None) == tag:
        return node
    for ch in getattr(node, "children", []):
        if isinstance(ch, (pegrex.Node, list)):
            r = find(ch, tag)
            if r is not None:
                return r
    return None


def test_fact_c():
    defs, _ = make_defs()
    start, rules = compile_grammar(C11_GRAMMAR, defs=defs)
    ast, err, pos = peg.run(start, FACT_C, rules, defs=defs)
    assert err is None, (err, pegrex.calcline(FACT_C, pos)[:2])
    assert find(ast, "compound-statement") is not None       # fn body
    assert find(ast, "selection-statement") is not None      # if/else
    assert find(ast, "jump-statement") is not None           # return
    # recursive call: argument-expression-list inside postfix suffix
    assert find(ast, "argument-expression-list") is not None


def test_typedef_context():
    defs, typedefs = make_defs()
    start, rules = compile_grammar(C11_GRAMMAR, defs=defs)
    ast, err, _ = peg.run(start, TYPEDEF_SRC, rules, defs=defs)
    assert err is None, err
    assert typedefs == {"myint"}


def test_declarations():
    defs, _ = make_defs()
    start, rules = compile_grammar(C11_GRAMMAR, defs=defs)
    for src in ["int a = 0;", "int *p;", "unsigned long x = 42;",
                "static const char *s = \"hi\";",
                "int arr[10] = {0};",
                "int add(int a, int b) { return a + b; }"]:
        _, err, pos = peg.run(start, src, rules, defs=defs)
        assert err is None, (src, err, pos)
