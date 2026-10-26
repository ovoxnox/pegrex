"""Deterministic SMT-LIB 2 export for the supported linear fragment."""
from __future__ import annotations
import hashlib, re
from .linsolve import parse_atom, LinearError
SCHEMA = "pegrex.smtlib-export.v1"


def export_smtlib(constraints, *, check_sat=True) -> dict:
    """Implement export smtlib with the module's explicit API and failure semantics."""
    atoms, symbols, unknowns = [], {}, []
    def symbol(name):
        """Implement symbol with the module's explicit API and failure semantics."""
        if name not in symbols: symbols[name] = f"v_{len(symbols)}"
        return symbols[name]
    try:
        for text in constraints:
            atom = parse_atom(text)
            if atom.k.denominator != 1 or any(c.denominator != 1 for _, c in atom.coeffs):
                raise LinearError("fractional coefficients outside QF_LIA export")
            atoms.append(atom)
            for name, _ in atom.coeffs: symbol(name)
    except (LinearError, TypeError, ValueError) as error:
        unknowns.append(str(error))
        return {"schema": SCHEMA, "schema_version": 1, "status": "unknown",
                "script": "", "symbols": symbols, "unknowns": unknowns}
    def expression(atom):
        """Implement expression with the module's explicit API and failure semantics."""
        terms = []
        for name, coeff in atom.coeffs:
            value, var = int(coeff), symbol(name)
            terms.append(var if value == 1 else f"(- {var})" if value == -1 else f"(* {value} {var})")
        lhs = terms[0] if len(terms) == 1 else "(+ " + " ".join(terms) + ")" if terms else "0"
        op = "=" if atom.op == "=" else atom.op
        return f"({op} {lhs} {int(atom.k)})"
    lines = ["(set-logic QF_LIA)"]
    lines += [f"(declare-fun {symbol(name)} () Int)" for name in sorted(symbols)]
    lines += [f"(assert {expression(atom)})" for atom in atoms]
    if check_sat: lines.append("(check-sat)")
    script = "\n".join(lines) + "\n"
    return {"schema": SCHEMA, "schema_version": 1, "status": "complete", "script": script,
            "script_sha256": hashlib.sha256(script.encode()).hexdigest(),
            "symbols": symbols, "constraints": len(atoms), "unknowns": []}


def crosscheck_smtlib(export) -> dict:
    """Optionally ask Z3 to parse and solve the emitted script; export needs no Z3."""
    if export.get("status") != "complete":
        return {"verdict": "unknown", "unknowns": ["incomplete SMT-LIB export"]}
    try:
        import z3
        solver = z3.Solver()
        solver.add(z3.parse_smt2_string(export["script"]))
        result = solver.check()
        verdict = "sat" if result == z3.sat else "unsat" if result == z3.unsat else "unknown"
        return {"verdict": verdict, "solver": "z3", "unknowns": [] if verdict != "unknown" else [str(result)]}
    except Exception as error:
        return {"verdict": "unknown", "unknowns": [f"SMT-LIB cross-check failed: {error}"]}
