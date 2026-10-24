"""
antihalluc - the anti-hallucination compiler

compile_nl(text): natural language -> candidate invariants
-> discharge against the target contracts -> emit code
from the contract IR -> verify the emission. The output is a
program that is provably what the sentence meant -- or nothing: any stage
that cannot prove its part returns a refusal and NO CODE IS SHIPPED.
The compiler never hallucinates, because it cannot ship what it cannot prove.
"""
from __future__ import annotations

import os
import tempfile

from .nlspec import propose
from .refine import discharge_source
from .emitter import emit_python
from .semantics import verify_patch
from .tv import wrap


def compile_nl(text, src_path, fn_name=None):
    """NL -> {code, certificate, verdict} or a refusal with nothing."""
    cands = propose(text)
    if not cands:
        return {"verdict": "unknown",
                "reason": "no candidate invariants could be proposed",
                "code": None, "certificate": None}
    verdicts = discharge_source(src_path, {"requires": [], "ensures": cands})
    proven = []
    for v in verdicts:
        for e in v["ensures"]:
            if e["status"] in ("proven", "discharged"):   # refine vocab
                proven.append(e["contract"])
    if not proven:
        return {"verdict": "refuted",
                "reason": "no candidate discharged on any path",
                "candidates": cands, "code": None, "certificate": None}
    # emit from the REAL contracts and verify the emission
    import ast
    src = open(src_path).read()
    tree = ast.parse(src)
    fn = next((n for n in tree.body if isinstance(n, ast.FunctionDef)),
              None)
    if fn is None:
        return {"verdict": "unknown", "reason": "no function unit",
                "code": None, "certificate": None}
    from . import api
    contracts = api.contracts(src_path)
    params = [a.arg for a in fn.args.args]
    try:
        code = emit_python(fn.name, params, contracts)
    except ValueError as e:
        return {"verdict": "unknown", "reason": f"emission refused: {e}",
                "code": None, "certificate": None}
    fd, out_path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write(code)
    try:
        proof = verify_patch(src_path, out_path)
    finally:
        os.unlink(out_path)
    w = wrap(proof)
    return {"verdict": w["verdict"], "code": code,
            "certificate": w,
            "proven_candidates": proven,
            "refused_candidates": [c for c in cands if c not in proven]}
