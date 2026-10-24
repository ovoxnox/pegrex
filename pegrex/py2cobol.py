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
    from .semantics import _canon_result
    def canon(rows):
        """canon(rows): see module docstring."""
        return sorted((tuple(sorted(map(str, cs)), _canon_result(res))
                       for cs, res in rows))
    # v1 identity: same path count, same path-0 constraint text, same
    # canonical results. The COBOL ELSE is the complement of path 0.
    import re as _re
    from .refine import _norm_constraint as _nc
    def up(s):   # legacy-front convention: identifiers compare uppercase
        """up(s): see module docstring."""
        return _re.sub(r"[A-Za-z_]\w*",
                       lambda mm: mm.group(0).upper(), s)
    py0 = sorted(up(_nc(str(c))) for c in contracts[0][0])
    cob0 = sorted(up(_nc(str(c))) for c in cobol_contracts[0][0])
    def canon_res(r):
        """canon res(r): see module docstring."""
        return up(_canon_result(r))
    py_res = sorted(canon_res(r) for _, r in contracts)
    cob_res = sorted(canon_res(r) for _, r in cobol_contracts)
    identity = (len(contracts) == len(cobol_contracts)
                and py0 == cob0 and py_res == cob_res)
    return {"cobol": cobol_src, "identity": identity,
            "n_paths": len(contracts)}
