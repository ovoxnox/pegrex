"""Property-based grammar generation and parser/IR/DSL round trips."""

from __future__ import annotations

import sys

import hypothesis.strategies as st
from hypothesis import HealthCheck, given, settings

from pegrex import compile_grammar, peg
from pegrex.gramir import lift, lift_grammar, lower, to_dsl


# peg.run uses a deep-recursion budget; establish it before Hypothesis starts
# so its own recursion-limit health checks remain stable.
sys.setrecursionlimit(max(sys.getrecursionlimit(), 100_000))


_LITERALS = st.text(alphabet=st.characters(min_codepoint=97, max_codepoint=122),
                    min_size=1, max_size=3)


def _literal(text: str):
    return (f"'{text}'", text)


@st.composite
def _patterns(draw):
    base = st.one_of(
        _LITERALS.map(_literal),
        _LITERALS.map(lambda text: (".", text[0])),
    )

    def extend(children):
        return st.one_of(
            st.tuples(children, children).map(
                lambda pair: (f"({pair[0][0]} {pair[1][0]})",
                              pair[0][1] + pair[1][1])),
            st.tuples(children, children, st.booleans()).map(
                lambda row: (f"({row[0][0]} / {row[1][0]})",
                             row[0][1] if row[2] else row[1][1])),
            st.tuples(children, st.booleans()).map(
                lambda row: (f"({row[0][0]})?", row[0][1] if row[1] else "")),
            st.tuples(children, st.integers(min_value=1, max_value=3)).map(
                lambda row: (f"({row[0][0]})^{row[1]}", row[0][1] * row[1])),
        )

    return draw(st.recursive(base, extend, max_leaves=8))


def _full(pattern):
    return peg.SeqP(pattern, peg.NotP(peg.AnyP()))


def _freeze(value):
    if isinstance(value, peg.Node):
        return (value.tag, value.pos, value.endpos,
                tuple(_freeze(child) for child in value.children))
    if isinstance(value, list):
        return tuple(_freeze(item) for item in value)
    return value


def _run(pattern, source, rules):
    value, error, position = peg.run(_full(pattern), source, rules)
    return _freeze(value), error, position


@settings(max_examples=60, derandomize=True, deadline=None,
          suppress_health_check=[HealthCheck.too_slow])
@given(pattern=_patterns())
def test_generated_grammar_ir_and_dsl_round_trip(pattern):
    fragment, example = pattern
    grammar = f"Root <-- {fragment}\nHelper <-- 'unused'\n"
    start, rules = compile_grammar(grammar)
    lifted = lift_grammar(rules)
    lowered_rules = {name: lower(ir) for name, ir in lifted.items()}

    dsl = to_dsl(lifted["Root"])
    dsl_start, dsl_rules = compile_grammar(f"Root <-- {dsl}\n")

    for source in (example, example + "!"):
        expected = _run(start, source, rules)
        assert _run(start, source, lowered_rules) == expected
        assert _run(dsl_start, source, dsl_rules) == expected


@settings(max_examples=40, derandomize=True, deadline=None)
@given(pattern=_patterns())
def test_lift_lower_is_structurally_lossless_for_supported_generated_nodes(pattern):
    fragment, _ = pattern
    _, rules = compile_grammar(f"Root <-- {fragment}\n")
    original = lift(rules["Root"])
    assert lift(lower(original)) == original
