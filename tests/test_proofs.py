try:
    import pytest
except ImportError:
    class _Raises:
        def __init__(self, exc): self.exc = exc
        def __enter__(self): return self
        def __exit__(self, t, v, tb):
            assert t is not None and issubclass(t, self.exc), f"expected {self.exc}"
            return True
    class _PytestShim:
        @staticmethod
        def raises(exc): return _Raises(exc)
    pytest = _PytestShim()


from fractions import Fraction

from pegrex.ir import lower_condition
from pegrex.linsolve import atoms_of
from pegrex.proofs import certified_infeasible, check_proof, derive_proof

CYCLE = atoms_of(lower_condition("x < y and y < z and z < x"))
FEASIBLE = atoms_of(lower_condition("x >= 1 and y >= x"))


def test_cycle_carries_checkable_certificate():
    out = certified_infeasible(CYCLE)
    assert out["infeasible"] and out["certificate"] and out["checked"]["ok"]


def test_feasible_system_no_certificate():
    assert derive_proof(FEASIBLE) is None
    out = certified_infeasible(FEASIBLE)
    assert out["infeasible"] is False and out["certificate"] is None


def test_tampered_multiplier_refused():
    out = certified_infeasible(CYCLE)
    lam = out["certificate"]["multipliers"]
    tampered = {"inputs": out["certificate"]["inputs"],
                "multipliers": [lam[0] * -1] + lam[1:]}
    chk = check_proof(CYCLE, tampered)
    assert chk["ok"] is False and "multiplier" in chk["reason"]


def test_malformed_certificates_refused():
    assert check_proof(CYCLE, {"multipliers": [Fraction(1)]})["ok"] is False
    assert check_proof(CYCLE, {"multipliers": [Fraction(0)] * len(CYCLE)})["ok"] is False


def test_cross_system_certificate_rejected():
    out = certified_infeasible(CYCLE)
    assert check_proof(FEASIBLE, out["certificate"])["ok"] is False
