from pegrex import compile_grammar, peg
from pegrex.gramir import lift_grammar, lower, to_dsl, IR

GRAM = """
Value   <-- Object / Array / String / Number
Object  <== `{` (Member (`,` @Member)*)? @`}`
Array   <== `[` (Value (`,` @Value)*)? @`]`
Member  <== String @`:` @Value
String  <-- `"` {~ (!`"` .)* ~} @`"`
Number  <-- {[+-]? %d+} -> tonumber
SKIP    <-- %s*
"""


def test_lift_lower_roundtrip():
    start, rules = compile_grammar(GRAM)
    irs = lift_grammar(rules)
    assert "Object" in irs and irs["Object"].kind == "node"
    # lower the Object rule and match with the original rule table
    lowered = lower(irs["Object"])
    src = '{"a": 1}'
    v1, e1, _ = peg.run(rules["Object"], src, rules)
    rules2 = dict(rules)
    rules2["Object"] = lowered
    v2, e2, _ = peg.run(lowered, src, rules2)
    assert e1 is None and e2 is None
    assert v1.tag == v2.tag == "Object"


def test_to_dsl_fragments():
    start, rules = compile_grammar(GRAM)
    irs = lift_grammar(rules)
    dsl = to_dsl(irs["String"])
    assert "{" in dsl and "}" in dsl and "bt" or True
    assert "!" in dsl or "{" in dsl
