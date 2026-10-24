import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))
#!/usr/bin/env python
"""End-to-end demo: grammar -> AST -> CFG -> path formulas -> SMT-LIB."""
from pegrex import compile_grammar, peg, prettyast
from pegrex.peg import Node
from pegrex.cfg import CFGBuilder, TagSpec
from pegrex.paths import PathEnumerator, linearize
from pegrex.sym import V, Sym, Add, Lt, Gt, const

# 1) parse with the PegRex grammar from the original project's README
grammar = open("examples/json.gram").read()
start, rules = compile_grammar(grammar)
src = '[{"string":"some\\ntext", "boolean":true, "number":-1.5e+2, "null":null}]'
ast, err, _ = peg.run(start, src, rules)
assert err is None
print(prettyast(ast))

# 2) CFG + path formulas for a control-flow snippet.
#    Conditions are tag-tagged nodes here ("cond" nodes carry a symbolic name).
def Cond(name):
    return Node("cond", 0, 0, [name])

func = Node("Block", 0, 0, [
    Node("If", 0, 0, [
        Cond("n>0"),
        Node("Block", 0, 0, [Node("Return", 0, 0, [Node("Id", 0, 0, ["n"])])]),
        Node("Block", 0, 0, [
            Node("While", 0, 0, [
                Cond("n<10"),
                Node("Block", 0, 0, [Node("Assign", 0, 0,
                    [Node("Id", 0, 0, ["n"]), Add(V("n"), const(1))])]),
            ])
        ]),
    ]),
    Node("Return", 0, 0, [Node("Id", 0, 0, ["n"])]),
])
cfg = CFGBuilder(TagSpec()).build(func)
print(cfg.to_dot())
for i, p in enumerate(PathEnumerator(cfg, unroll=1).enumerate()):
    f = linearize(cfg, p, {"Assign": lambda st, env: (st.children[0].children[0], st.children[1])})
    print(f"--- path {i}: {p}")
    print(f.smt2())
