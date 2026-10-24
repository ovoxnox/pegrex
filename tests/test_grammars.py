import pathlib
import subprocess
import sys
import pegrex

ROOT = pathlib.Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))


def test_lint_all_grammars():
    grams = sorted((ROOT / "examples").glob("*.gram"))
    r = subprocess.run([sys.executable, "tools/grammar_lint.py"]
                       + [str(g) for g in grams],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout
    assert "0 problem(s)" in r.stdout


def test_all_grammars_compile():
    from pegrex import compile_grammar
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

    defs = {"is_typedef": is_typedef, "set_typedef": set_typedef}
    for g in sorted((ROOT / "examples").glob("*.gram")):
        start, rules = compile_grammar(g.read_text(),
                                       defs=defs if "c11" in g.name else None)
        assert start is not None and rules, g.name



def test_new_grammars_parse():
    from pegrex import compile_grammar, peg
    sstart, srules = compile_grammar(
        (ROOT / "examples" / "sexpr.gram").read_text())
    ast, err, _ = peg.run(sstart, "(add 1 (mul 2 3))", srules)
    assert err is None and ast.tag == "SExpr"
    istart, irules = compile_grammar(
        (ROOT / "examples" / "ini.gram").read_text())
    ini = "[server]\nhost = example.com\nport = 8080\n"
    iast, err, _ = peg.run(istart, ini, irules)
    assert err is None
    assert iast.children[0].tag == "Section"
    assert iast.children[1].children[0] == "host"  # Entry: [Key, Value]


def test_csv_url_grammars():
    from pegrex import compile_grammar, peg
    cstart, crules = compile_grammar(
        (ROOT / "examples" / "csv.gram").read_text(),
        defs={"squote": lambda *_: "'"})
    _, err, _ = peg.run(cstart, "a,'b''c',d", crules)
    assert err is None
    ustart, urules = compile_grammar(
        (ROOT / "examples" / "url.gram").read_text())
    uast, err, _ = peg.run(ustart, "https://example.com:8080/a/b?q=1", urules)
    assert err is None and uast.tag == "Url"
