"""
testsynth

║  Coverage-gap -> test synthesis: each uncovered path's constraints are a  
║  formula; the SMT model is a concrete input. Emit a ready-made test."""

from __future__ import annotations

from dataclasses import dataclass

from .coverage import coverage_gaps
from .smt import learn


@dataclass
class SynthesizedTest:
    """SynthesizedTest - see module docstring."""
    constraints: list
    inputs: dict   # var -> concrete value satisfying the constraints
    test_body: str # ready-to-paste pytest test


def _model(atoms):
    """Extract one concrete integer per variable from the bounds model."""
    m = learn(atoms)
    out = {}
    for var, (lo, li, hi, hi_inc, neq) in m.bounds.items():
        v = lo if lo is not None else (hi if hi is not None else 0)
        v = int(v)
        if lo is not None and hi is not None and lo == hi:
            v = int(lo)
        while v in neq:
            v += 1
        out[var.split("@")[0]] = v
    return out


def synthesize_tests(cfg, cond, cov_lines, fn_name, unroll=2) -> list[SynthesizedTest]:
    """For every satisfiable-but-uncovered path: model the constraints,
    emit a test that would cover it."""
    out = []
    for g in coverage_gaps(cfg, cond, cov_lines, unroll=unroll):
        atoms = [c for c in g["constraints"]]
        inputs = _model(atoms)
        args = ", ".join(f"{k}={v}" for k, v in sorted(inputs.items()))
        body = (f"def test_{fn_name}_gap_{len(out)}():\n"
                f"    # covers: {' and '.join(atoms)}\n"
                f"    assert {fn_name}({args}) is not None")
        out.append(SynthesizedTest(sorted(set(atoms)), inputs, body))
    return out
