"""
modernize - legacy modernization factory

COBOL / Fortran -> Python through the contract IR, with an EQUivalence
certificate attached (cross-language verify_patch). The certificate is the
product: the emitted Python is only shipped when the proof says the
behaviour is identical. Targets without a certified emitter (Rust/Go)
return UNKNOWN evidence and no code -- never a fake equivalence claim."""

from __future__ import annotations

import re
import tempfile
import os

from . import api
from .emitter import emit_python
from .semantics import verify_patch


def _legacy_params(contracts):
    free = set()
    for cs, res in contracts:
        for c in cs:
            free |= set(re.findall(r"[A-Za-z_]\w*", str(c)))
        free |= set(re.findall(r"[A-Za-z_]\w*", str(res)))
    return sorted(v for v in free
                  if v not in ("and", "or", "not", "true", "false", "result"))


def _legacy_fn_name(src, path):
    m = re.search(r"PROGRAM-ID\.\s*(\w+)", src, re.I)
    if m:
        return m.group(1).lower()
    m = re.search(r"function\s+(\w+)", src, re.I)
    if m:
        return m.group(1).lower()
    return os.path.splitext(os.path.basename(path))[0].lower()


def modernize(src_path, target="python", copydir=None) -> dict:
    """Legacy source -> target language with an equivalence certificate.

    copydir: for COBOL sources with COPY copybooks, the directory books
    are resolved in (extensions tried: .cpy .CPY .cob .txt). Given, the
    source is expanded first and the certificate is checked against the
    expanded source. None keeps the old behavior; COPY statements then
    hit the COBOL frontend, which refuses loudly (CobolError)."""
    with open(src_path, encoding="utf-8") as source_file:
        src = source_file.read()
    if target != "python":
        note = (f"{target} emission is not certified for this legacy adapter -- "
                "no equivalence claim is made for uncertified targets")
        return {"target": target, "code": None, "candidate_code": None,
                "verified": None, "verdict": "unknown", "unknowns": [note],
                "note": note}
    expanded_tmp = None
    ext = os.path.splitext(src_path)[1].lower()
    if ext in (".cob", ".cbl", ".cobol") and copydir is not None:
        from . import cobolfront
        src = cobolfront.expand_copybooks(src, copydir)
        fd, expanded_tmp = tempfile.mkstemp(suffix=ext or ".cob")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(src)
        src_path = expanded_tmp
    contracts = api.contracts(src_path)  # native frontend via ext
    params = _legacy_params(contracts)
    name = _legacy_fn_name(src, src_path)
    code = emit_python(name, params, contracts)
    fd, out_path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(code)
    try:
        proof = verify_patch(src_path, out_path)
    finally:
        os.unlink(out_path)
        if expanded_tmp is not None:
            os.unlink(expanded_tmp)
    counterexample = proof.get("counterexample") or {}
    verdict = ("proved" if proof.get("verified") is True else
               "refuted" if counterexample.get("confirmed") is True else "unknown")
    unknowns = [] if verdict != "unknown" else [
        proof.get("note") or "semantic verification did not prove equivalence"]
    return {"target": "python", "function": name,
            "code": code if verdict == "proved" else None,
            "candidate_code": code, "verified": verdict == "proved",
            "verdict": verdict, "unknowns": unknowns,
            "certificate": proof, "counterexample": proof.get("counterexample")}
