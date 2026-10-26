"""Pragmatic Why3, SMT-LIB, Lean, and Coq export; external proof stays external."""
from __future__ import annotations

import hashlib

from .linsolve import LinearError, parse_atom
from .smtlib import export_smtlib

SCHEMA = "pegrex.prover-bridge.v1"


def _infix(atom, target):
    terms = []
    for name, coefficient in atom.coeffs:
        value = int(coefficient)
        variable = name if target == "why3" else name
        terms.append(variable if value == 1 else f"(- {variable})" if value == -1 and target == "smtlib"
                     else f"({value} * {variable})")
    expression = " + ".join(terms) if terms else "0"
    operator = "=" if atom.op == "=" else atom.op
    return f"({expression} {operator} {int(atom.k)})"


def _variables(atoms):
    names = sorted({name for atom in atoms for name, _ in atom.coeffs})
    for name in names:
        if not name.isidentifier():
            raise LinearError(f"unsupported prover variable name: {name}")
    return names


def _proposition(atoms, claim, target):
    conditions = [_infix(atom, target) for atom in atoms]
    joiner = " /\\ " if target in {"why3", "lean", "coq"} else " and "
    conjunction = "(" + joiner.join(conditions) + ")" if conditions else "true"
    if claim is None:
        return conjunction, False
    return f"({conjunction} -> {_infix(claim, target)})", True


def export_prover(constraints, *, target, claim=None) -> dict:
    """Export the linear fragment with an explicit unchecked proof status."""
    target = target.lower()
    try:
        atoms = [parse_atom(row) for row in constraints]
        goal_atom = parse_atom(claim) if claim is not None else None
        for atom in atoms + ([goal_atom] if goal_atom else []):
            if atom.k.denominator != 1 or any(coefficient.denominator != 1 for _, coefficient in atom.coeffs):
                raise LinearError("fractional coefficients are outside the integer prover bridge")
        names = _variables(atoms + ([goal_atom] if goal_atom else []))
        if target == "smtlib":
            exported = export_smtlib(constraints, check_sat=True)
            if exported["status"] != "complete":
                raise LinearError("; ".join(exported["unknowns"]))
            script = exported["script"]
            if claim is not None:
                raise LinearError("SMT-LIB implication export requires a solver-side negated goal; use Why3, Lean, or Coq")
        else:
            proposition, implication = _proposition(atoms, goal_atom, target)
            if target == "why3":
                binders = " ".join(f"{name}:int" for name in names)
                quantifier = "forall" if implication else "exists"
                body = f"{quantifier} {binders}. {proposition}" if names else proposition
                script = "theory PegRexBridge\n  use import int.Int\n" + f"  goal pegrex_goal: {body}\nend\n"
            elif target == "lean":
                binders = " ".join(f"({name} : Int)" for name in names)
                quantifier = "∀" if implication else "∃"
                body = f"{quantifier} {binders}, {proposition}" if names else proposition
                script = "import Mathlib\n\n" + f"theorem pegrex_goal : {body} := by\n  sorry -- EXTERNAL PROOF REQUIRED\n"
            elif target == "coq":
                binders = " ".join(f"({name}:Z)" for name in names)
                quantifier = "forall" if implication else "exists"
                body = f"{quantifier} {binders}, {proposition}" if names else proposition
                script = "Require Import ZArith.\nOpen Scope Z_scope.\n" + f"Theorem pegrex_goal : {body}.\nProof.\nAdmitted. (* EXTERNAL PROOF REQUIRED *)\n"
            else:
                raise ValueError(f"unsupported prover target: {target}")
        return {"schema": SCHEMA, "schema_version": 1, "target": target,
                "status": "exported", "verdict": "unknown", "proof_status": "not-checked",
                "script": script, "script_sha256": hashlib.sha256(script.encode()).hexdigest(),
                "variables": names, "unknowns": ["export is not a proof; an external prover must check it"]}
    except (LinearError, TypeError, ValueError) as error:
        return {"schema": SCHEMA, "schema_version": 1, "target": target,
                "status": "unknown", "verdict": "unknown", "proof_status": "not-checked",
                "script": "", "unknowns": [f"prover export failed: {error}"]}


def check_prover_export(export, checker) -> dict:
    """Attach independent external-checker evidence without trusting a label."""
    if export.get("status") != "exported":
        return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown",
                "proof_status": "not-checked", "unknowns": ["incomplete prover export"]}
    try:
        evidence = checker(export["target"], export["script"])
        verdict = evidence.get("verdict") if isinstance(evidence, dict) else "unknown"
        if verdict == "proved" and not evidence.get("proof"):
            verdict = "unknown"
        if verdict == "refuted" and not (evidence.get("counterexample") or {}).get("confirmed"):
            verdict = "unknown"
        if verdict not in {"proved", "refuted", "unknown"}:
            verdict = "unknown"
        result = dict(export, verdict=verdict,
                      proof_status="checked" if verdict != "unknown" else "not-checked",
                      external_evidence=evidence)
        result["unknowns"] = [] if verdict != "unknown" else ["external prover did not prove or confirmed-refute the export"]
        return result
    except Exception as error:
        return dict(export, verdict="unknown", proof_status="not-checked",
                    unknowns=[f"external prover failed: {error}"])
