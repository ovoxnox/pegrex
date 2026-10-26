from pegrex.invariants import infer_invariants, validate_invariants
from pegrex.ir import lower_condition
from pegrex.linsolve import atoms_of


def test_entry_initiation_does_not_assume_loop_guard():
    result = infer_invariants("i <= n", {"i": 1}, ["i = 1"])
    assert "i <= n + 1" not in result["invariants"]
    assert result["proof_obligations"]["i <= n + 1"]["initiation"] == "not_entailed"


def test_unmodeled_mutation_is_unknown_and_not_validated():
    result = validate_invariants("i < 4", {}, ["i = 0"], ["i >= 0"])
    assert result["invariants"] == []
    assert result["status"] == "unknown"
    assert result["proof_obligations"]["i >= 0"]["consecution"] == "unknown"


def test_validated_invariant_has_both_proof_obligations():
    result = validate_invariants("i < 4", {"i": 1}, ["i = 0"], ["i >= 0"])
    assert result["invariants"] == ["i >= 0"]
    assert result["proof_obligations"]["i >= 0"] == {
        "initiation": "entailed", "consecution": "entailed"}
    assert result["status"] == "ok"
