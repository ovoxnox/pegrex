
import pathlib, sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pegrex.smt import learn, entails
from pegrex.idioms import IdiomRule, guard_holds
from pegrex.summaries import compose


def test_smt_basics():
    assert entails(learn(["(n = 0)"]), "(n = 0)")
    assert not entails(learn(["(n = 0)"]), "(n > 0)")
    assert entails(learn(["(not (n < 0))"]), "(n >= 0)")
    assert not learn(["(n < 0)", "(n > 5)"]).feasible()
    assert not learn(["(n = 3)", "(not (n = 3))"]).feasible()
    assert entails(learn(["(x < 0)"]), "(not (x >= 0))")


def test_guard_implication_fires():
    cons = [frozenset({"(not (n < 0))"})]
    rule = IdiomRule("g", ["If"], "X", path_guard="(n >= 0)")
    assert guard_holds(rule, cons)


def test_guard_not_implied():
    cons = [frozenset({"(n < 0)"})]
    rule = IdiomRule("g", ["If"], "X", path_guard="(n > 0)")
    assert not guard_holds(rule, cons)


def test_compose_prunes_infeasible():
    caller = [(frozenset({"(n < 0)"}), "clamp(n) + 1")]
    callee = [(frozenset({"(x < 0)"}), "0"),
              (frozenset({"(x >= 0)"}), "x")]
    out = compose(caller, "clamp", callee, param="x", arg="n")
    assert len(out) == 1 and out[0][1] == "0 + 1", out
