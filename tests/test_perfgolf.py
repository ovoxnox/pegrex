from pegrex.eggx import validate_rule
from pegrex.perfgolf import SOUND_RULES, rank_equivalent_forms


def test_all_builtin_identities_are_sound():
    assert all(v["sound"] for _, v in SOUND_RULES)


def test_connects_add_and_mul_forms_with_equal_cost():
    out = rank_equivalent_forms(["x + x", "2 * x", "x * 2"])
    assert out["status"] == "ranked"
    assert {r["cost"] for r in out["ranked"]} == {1}


def test_ranks_as_written_cost_not_class_cheapest():
    out = rank_equivalent_forms(["(n + 0) + 0", "n"])
    assert out["status"] == "ranked"
    costs = {r["expr"]: r["cost"] for r in out["ranked"]}
    assert costs["(n + 0) + 0"] == 2
    assert costs["n"] == 0
    assert out["ranked"][0]["expr"] == "n"


def test_cheapest_in_class_can_beat_every_input():
    # neither input is the literal string "n", but the class's cheapest
    # constructible member still collapses to it
    out = rank_equivalent_forms(["(n + 0) + 0", "(0 + n) + 0"])
    assert out["status"] == "ranked"
    assert out["cheapest_cost"] == 0
    assert out["cheapest_in_class"] == "n"
    assert all(r["cost"] == 2 for r in out["ranked"])


def test_refuses_to_rank_unconnected_expressions():
    out = rank_equivalent_forms(["a + b", "a * b"])
    assert out["status"] == "unconnected"
    assert out["distinct_classes"] == 2


def test_extra_rule_must_be_oracle_validated_to_connect():
    unsound = validate_rule(lambda x: x + 1, lambda x: x, name="bad")
    assert not unsound["sound"]
    bad_rule = (("add", "?a", 1), "?a")
    out = rank_equivalent_forms(["a + 1", "a"],
                                extra_rules=[(bad_rule, unsound)])
    assert out["status"] == "unconnected", out
    assert any(not r.get("sound", True)
              for r in out["refused_rules"] if isinstance(r, dict))


def test_extra_rule_connects_when_sound():
    distrib = validate_rule(
        lambda p: p[0] * (p[1] + 1), lambda p: p[0] * p[1] + p[0],
        samples=[(a, b) for a in range(-3, 4) for b in range(-3, 4)],
        name="x*(y+1)=x*y+x")
    assert distrib["sound"]
    rule = (("mul", "?a", ("add", "?b", 1)), ("add", ("mul", "?a", "?b"), "?a"))
    out = rank_equivalent_forms(["a * (b + 1)", "a * b + a"],
                                extra_rules=[(rule, distrib)])
    assert out["status"] == "ranked"


def test_unsupported_syntax_raises_clear_error():
    try:
        rank_equivalent_forms(["a / b"])
        assert False, "division is outside the supported fragment"
    except ValueError as e:
        assert "unsupported" in str(e)
