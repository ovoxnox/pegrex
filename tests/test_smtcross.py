import pytest
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pegrex import smt
from pegrex.smt import Backend, crosscheck, get_backend, set_backend


def test_crosscheck_agrees_with_z3():
    pytest.importorskip("z3", reason="Z3 cross-check is optional")
    r = crosscheck(["(x >= 0)", "(x <= 10)", "(y = 3)"], n=64, seed=1)
    assert r["refusal"] is None
    assert r["agree"] is True and not r["witnesses"]
    assert r["queries"] >= 65  # 64 guards + feasibility


def test_crosscheck_refuses_out_of_fragment():
    r = crosscheck(["(x + y <= 5)"])
    assert r["agree"] is None
    assert "outside cross-check fragment" in r["refusal"]


def test_crosscheck_catches_disagreeing_backend():
    pytest.importorskip("z3", reason="Z3 cross-check is optional")
    class Liar(Backend):
        def entails(self, model, guard):
            return True

    old = get_backend()
    set_backend(Liar())
    try:
        r = crosscheck(["(x >= 0)"], guards=["(x <= 5)", "(x = 0)"])
    finally:
        set_backend(old)
    assert r["agree"] is False
    assert any(w["z3"] is False and w["backend"] is True
               for w in r["witnesses"])
    # backend restoration visible to subsequent checks
    assert crosscheck(["(x >= 0)"], guards=["(x <= 5)"])["agree"] is True


def test_crosscheck_refuses_without_z3():
    orig = smt._z3
    smt._z3 = lambda: (_ for _ in ()).throw(
        smt.SMTCrosscheckError("z3 not installed; refusing"))
    try:
        r = crosscheck(["(x >= 0)"])
    finally:
        smt._z3 = orig
    assert r["agree"] is None and "refusing" in r["refusal"]


def test_crosscheck_deterministic():
    atoms = ["(x >= 0)", "(x <= 4)"]
    assert crosscheck(atoms, n=16, seed=9) == crosscheck(atoms, n=16, seed=9)


def test_auto_feasible_negated_atom_not_inverted():
    # regression: _to_z3 dropped z3.Not on negated atoms, so "(not (x < 2))"
    # was checked as x < 2 -- the exact opposite constraint. With
    # x <= 0 in the set, x < 2 is trivially satisfiable but x >= 2 is not.
    from pegrex.smt import auto_feasible
    assert auto_feasible(["(x <= 0)", "(not (x < 2))"]) is False
    assert auto_feasible(["(x >= 5)", "(not (x < 2))"]) is True
