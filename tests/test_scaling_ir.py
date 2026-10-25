"""Immutable IR interning and memoized solver operations."""
from dataclasses import FrozenInstanceError
from fractions import Fraction

import pytest

from pegrex.ir import Expr, linearize, parse_expr
from pegrex.linsolve import LinearBackend, _implication_probe_feasible
from pegrex.sym import Add, Ge, Mul, Op, Sym, V, canonical


def test_expression_nodes_are_hash_consed_and_immutable():
    assert Sym("x") is V("x")
    assert Op("+", (V("x"), 1)) is Add(V("x"), 1)
    assert Expr("var", "int", "x") is Expr("var", "int", "x")
    assert parse_expr("x + 1") is parse_expr("x + 1")
    with pytest.raises(FrozenInstanceError):
        V("x").name = "y"


def test_canonicalization_is_memoized():
    canonical.cache_clear()
    first = canonical(Add(V("x"), 1))
    before = canonical.cache_info().hits
    second = canonical(Add(1, V("x")))
    assert first == second
    assert canonical.cache_info().hits > before


def test_linearization_cache_does_not_expose_mutable_cached_dicts():
    linearize.cache_clear()
    expr = Add(Mul(2, V("x")), V("y"))
    first = linearize(expr)
    assert first == ({"x": Fraction(2), "y": Fraction(1)}, Fraction(0))
    first[0]["x"] = Fraction(999)
    hits = linearize.cache_info().hits
    assert linearize(expr) == ({"x": Fraction(2), "y": Fraction(1)}, Fraction(0))
    assert linearize.cache_info().hits == hits + 1


def test_implication_subqueries_are_memoized():
    _implication_probe_feasible.cache_clear()
    backend = LinearBackend()
    model = backend.learn(["(x >= 0)"])
    guard = Ge(V("x"), 0)
    assert backend.entails(model, guard) is True
    before = _implication_probe_feasible.cache_info().hits
    assert backend.entails(model, guard) is True
    assert _implication_probe_feasible.cache_info().hits > before
    assert backend.entails(model, Ge(V("y"), 0)) is False
