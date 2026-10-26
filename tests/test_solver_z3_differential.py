"""Differential QF_LIA checks against the locked Z3 oracle.

Fourier--Motzkin elimination is complete over rationals but deliberately
incomplete over integers.  These tests therefore reject unsound decisions
while counting (not hiding) integer cases where the internal engine cannot
produce either a contradiction or a concrete model.
"""

from __future__ import annotations

import random

import pytest
import z3

from pegrex.linsolve import LinearBackend, LinearError, parse_atom
from pegrex.smt import _to_z3, _z3_entails, _z3_feasible


OPERATORS = ("<", "<=", ">", ">=", "=", "!=")


def _atom_text(rng: random.Random) -> str:
    variables = "xyz"[: rng.randint(1, 3)]
    terms = []
    for variable in variables:
        coefficient = rng.randint(-3, 3)
        if coefficient:
            terms.append(f"{coefficient}*{variable}")
    if not terms:
        terms = [f"{rng.choice((-2, -1, 1, 2))}*{rng.choice(variables)}"]
    lhs = " + ".join(terms).replace("+ -", "- ")
    return f"({lhs} {rng.choice(OPERATORS)} {rng.randint(-5, 5)})"


def _cases(count: int = 400):
    rng = random.Random(0x5EED)
    for _ in range(count):
        yield [_atom_text(rng) for _ in range(rng.randint(1, 3))]


def _z3_model_satisfies(atoms: list[str], values: dict[str, int]) -> bool:
    solver = z3.Solver()
    solver.add(*[_to_z3(z3, atom) for atom in atoms])
    solver.add(*[z3.Int(name) == value for name, value in values.items()])
    return solver.check() == z3.sat


@pytest.mark.parametrize(
    ("atoms", "expected"),
    [
        (["(x < 1)", "(x >= 1)"], False),
        (["(x <= 0)", "(x > 0)"], False),
        (["(x >= 2)", "(x < 3)"], True),
        (["(x > -2)", "(x <= -1)"], True),
        (["(2*x = 4)", "(x != 2)"], False),
        (["(x != 3)", "(x >= 3)"], True),
        (["(x + y = 4)", "(x - y = 2)"], True),
        (["(2*x = 1)"], False),  # rational relaxation is SAT, QF_LIA is not
        (["(2*x + 2*y = 3)"], False),
        (["(2*x != 4)", "(2*x = 4)"], False),
    ],
)
def test_supported_integer_operators_match_z3_on_decided_cases(atoms, expected):
    backend = LinearBackend()
    model = backend.learn(atoms)
    assert _z3_feasible(z3, atoms) is expected
    if not expected:
        # A concrete model must never be manufactured for a Z3 contradiction.
        assert model.model() == {}
    elif backend.feasible(model):
        values = model.model()
        assert values
        assert _z3_model_satisfies(atoms, values)


def test_randomized_feasibility_is_sound_and_incompleteness_is_visible():
    checked = 0
    incomplete = 0
    seen = set()
    for atoms in _cases():
        seen.update(parse_atom(atom).op for atom in atoms)
        oracle = _z3_feasible(z3, atoms)
        backend = LinearBackend()
        model = backend.learn(atoms)
        if not backend.feasible(model):
            assert not oracle, {"atoms": atoms, "internal": "unsat", "z3": "sat"}
        else:
            values = model.model()
            if values or not model.vars:
                assert oracle, {"atoms": atoms, "model": values}
                assert _z3_model_satisfies(atoms, values)
            else:
                # FM's rational relaxation can be feasible when QF_LIA is not.
                # No model means no positive feasibility claim in this harness.
                incomplete += 1
        checked += 1
    assert checked == 400
    assert seen == set(OPERATORS)
    assert incomplete > 0  # the suite actually exercises the documented boundary


def test_randomized_entailment_never_disagrees_on_proofs():
    rng = random.Random(0xE17A11)
    checked = 0
    proofs = 0
    for atoms in _cases(250):
        backend = LinearBackend()
        model = backend.learn(atoms)
        guard = _atom_text(rng)
        verdict = backend.entails_with_status(model, guard)["status"]
        oracle = _z3_entails(z3, atoms, guard)
        if verdict == "entailed":
            proofs += 1
            assert oracle, {"atoms": atoms, "guard": guard}
        else:
            # not_entailed is a failed proof, not permission to discard UNKNOWN.
            assert verdict in {"not_entailed", "unknown"}
        checked += 1
    assert checked == 250
    assert proofs > 0


def test_coupled_disequality_reconstruction_defers_unassigned_variables():
    atoms = ["(x + y != 3)", "(x >= 0)", "(y >= 0)"]
    model = LinearBackend().learn(atoms).model()
    assert model
    assert _z3_model_satisfies(atoms, model)


def test_exact_rational_z3_translation_and_internal_refusal():
    atom = "(1/2*x <= 3/4)"
    expression = _to_z3(z3, atom)
    solver = z3.Solver()
    solver.add(expression, z3.Int("x") >= 2)
    assert solver.check() == z3.unsat
    with pytest.raises(LinearError, match="fractional atom"):
        LinearBackend().learn([atom])
