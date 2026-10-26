from pegrex.modelcheck import bounded_check, check_invariant_bounded
from pegrex.ir import lower_condition


def increment(state, depth):
    return [] if state["n"] >= 3 else [{"n": state["n"] + 1}]


def test_finite_graph_exhaustion_can_prove_invariant():
    result = bounded_check([{"n": 0}], increment,
                           lambda state: 0 <= state["n"] <= 3, max_depth=5)
    assert result["verdict"] == "proved"
    assert result["holds"] is True and result["complete"] is True


def test_transition_bound_is_visible_and_not_unbounded_proof():
    result = bounded_check([{"n": 0}], increment,
                           lambda state: state["n"] >= 0, max_depth=1)
    assert result["verdict"] == "unknown"
    assert result["holds"] is None
    assert result["bound"] == {"max_depth": 1, "max_states": 10000, "reached": True}
    assert result["counterexample"] is None


def test_counterexample_contains_exact_transition_trace():
    result = bounded_check([{"n": 0}], increment,
                           lambda state: state["n"] < 2, max_depth=4)
    assert result["verdict"] == "refuted"
    assert result["counterexample"]["states"] == [{"n": 0}, {"n": 1}, {"n": 2}]
    assert result["counterexample"]["transition_count"] == 2


def test_state_cap_and_undecided_invariant_are_unknown():
    capped = bounded_check([{"n": 0}], increment, lambda state: True,
                           max_depth=5, max_states=2)
    assert capped["verdict"] == "unknown" and capped["bound"]["reached"]
    undecided = bounded_check([{"n": 0}], lambda state, depth: [],
                              lambda state: None, max_depth=2)
    assert undecided["verdict"] == "unknown"


def test_constraint_adapter_exposes_unchecked_suffix():
    result = check_invariant_bounded([["x >= 0"], ["x >= 1"]],
                                     lower_condition("x >= 0"), max_depth=0)
    assert result["verdict"] == "unknown"
    assert result["bound"]["reached"] is True
