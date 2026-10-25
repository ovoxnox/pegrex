"""
py2cobol - the reverse modernization: Python -> COBOL from the
contract IR, then round-trip verification: contracts(Python) ==
contracts(generated COBOL). The certificate is the identity across both
contract spaces."""

from __future__ import annotations

import tempfile
import os

from . import api


def emit_cobol(name, params, contracts):
    """Contract IR -> COBOL source (straight-line branchy subset)."""
    lines = ["       IDENTIFICATION DIVISION.",
             "       PROGRAM-ID. " + name.upper() + ".",
             "       *> pegrex: result RES",
             "       PROCEDURE DIVISION."]
    if len(contracts) != 2:
        raise ValueError("py2cobol: v1 emits exactly 2-path functions -- "
                         "refusing rather than guessing")
    (cs0, res0), (_cs1, res1) = contracts
    cond0 = " AND ".join(str(c).replace("==", "=") for c in sorted(cs0))
    # idiomatic IF/ELSE: the ELSE branch is the set-theoretic complement
    # of path 0 (v1 identity is documented in round_trip)
    lines.append("           IF " + cond0 + " THEN")
    lines.append("               COMPUTE RES = " + str(res0))
    lines.append("           ELSE")
    lines.append("               COMPUTE RES = " + str(res1))
    lines.append("           END-IF.")
    lines.append("           GOBACK.")
    return chr(10).join(lines) + chr(10)


def round_trip(src_path):
    """Python -> COBOL -> verify the contract identity."""
    contracts = api.contracts(src_path)
    import ast
    tree = ast.parse(open(src_path).read())
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef))
    cobol_src = emit_cobol(fn.name, [a.arg for a in fn.args.args], contracts)
    fd, cob_path = tempfile.mkstemp(suffix=".cob")
    with os.fdopen(fd, "w") as f:
        f.write(cobol_src)
    try:
        cobol_contracts = api.contracts(cob_path)
    finally:
        os.unlink(cob_path)
    import re as _re
    from .refine import _norm_constraint
    from .semantics import _canon_result, _int_canon

    def up(text):
        """COBOL's case-insensitive identifiers share one canonical case."""
        return _re.sub(r"[A-Za-z_]\w*", lambda m: m.group(0).upper(), text)

    def canon(rows):
        # Compare complete (constraints, outcome) paths in the same integer
        # and linear-expression normal forms used by semantic verification.
        return { (frozenset(up(_int_canon(_norm_constraint(str(c)))) for c in cs),
                  up(_canon_result(res))) for cs, res in rows }

    identity = canon(contracts) == canon(cobol_contracts)
    return {"cobol": cobol_src, "identity": identity,
            "n_paths": len(contracts)}
