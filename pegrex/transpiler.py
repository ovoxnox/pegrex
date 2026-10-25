"""transpiler.py -- cross-language transpiler certification at scale:
A -> B with the bisimulation proof attached.  The pipeline API's product
form: paste code, receive certified-equivalent code + the proof bundle."""
from __future__ import annotations

import json
import pathlib


def _target_stub(fn: str, lang: str, paths: int) -> str:
    """Minimal compilable stub in the target language."""
    if lang in ("javascript", "typescript"):
        return f"// pegrex-generated stub: verify against {paths} paths\n" \
               f"function {fn}(n) {{ throw new Error('unverified stub'); }}\n"
    if lang == "c":
        return (f"/* pegrex-generated stub */\n"
                f"int {fn}(int n) {{ return 0; /* verify {paths} paths */ }}\n")
    return f"# pegrex-generated stub ({lang}): verify {paths} paths\n"


def transpile(source_path: str, target_lang: str,
              out_path: str | None = None) -> dict:
    """Legacy bundle-shaped entry point -- a thin adapter over
    transpile_certified (the one real implementation below).
    Kept only for the pre-existing bundle shape (api.py re-exports this
    name; certificate checks this exact shape): "paths" is still the
    raw CFG path list, but "proof" is now transpile_certified's real
    verify_patch result when the target is python, or an honestly-labeled
    stub note otherwise -- never the old placeholder string that claimed
    a bisimulation method without ever running one."""
    from pegrex.cfg import CFGBuilder
    from pegrex.paths import PathEnumerator
    from pegrex.languages import detect_language, get_contract_frontend
    src = pathlib.Path(source_path).read_text(encoding="utf-8")
    lang = detect_language(source_path)
    if lang is None:
        raise ValueError(f"transpiler: unknown source language for {source_path!r}")
    parse, tags, mk = get_contract_frontend(lang)()
    body = parse(src)
    cfg = CFGBuilder(tags).build(body)
    cfg_paths = PathEnumerator(cfg, unroll=2).enumerate()
    fn_name = pathlib.Path(source_path).stem
    out = transpile_certified(source_path, target=target_lang)
    bundle = {
        "source": source_path, "target_lang": target_lang,
        "paths": [[b for b in p] for p in cfg_paths],
        "target_stub": out.get("code")
                       or _target_stub(fn_name, target_lang, len(cfg_paths)),
        "proof": out["proof"] if out.get("proof") is not None else {
            "kind": "stub", "paths": len(cfg_paths),
            "method": out.get("note", "portable-data stub; no proof run")},
    }
    if out_path:
        pathlib.Path(out_path).write_text(json.dumps(bundle, indent=1))
    return bundle

def certified_python_transpile(src_path: str) -> dict:
    """Python -> Python through the contract IR, with the equivalence proof
    attached. Emission is not trusted: verify_patch certifies the output;
    on refusal the bundle carries the counterexample instead of code."""
    from . import api
    from .emitter import emit_python
    from .semantics import verify_patch
    import tempfile, os
    contracts = api.contracts(src_path)
    fn_name = None
    import ast as _ast
    tree = _ast.parse(open(src_path).read())
    fns = [n.name for n in tree.body if isinstance(n, _ast.FunctionDef)]
    if not fns:
        raise ValueError("transpiler: no function to transpile")
    fn_name = fns[0]
    sig_params = [a.arg for n in tree.body if isinstance(n, _ast.FunctionDef)
                  for a in n.args.args]
    code = emit_python(fn_name, sig_params, contracts)
    fd, out_path = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write(code)
    try:
        proof = verify_patch(src_path, out_path)
    finally:
        os.unlink(out_path)
    return {"target": "python", "code": code, "proof": proof,
            "verified": bool(proof.get("verified")),
            "counterexample": proof.get("counterexample")}


def transpile_certified(src_path: str, target: str = "python") -> dict:
    """Unified entry point (production API; the legacy 3-arg
    transpile(src, target, out_path) JSON emitter is unchanged above).

    python  -> certified_python_transpile (real code + proof)
    other   -> _target_stub (portable-data half, honest stub)"""
    if target == "python":
        return certified_python_transpile(src_path)
    fn = None
    import ast as _ast
    tree = _ast.parse(open(src_path).read())
    for n in tree.body:
        if isinstance(n, _ast.FunctionDef):
            fn = n.name
    if fn is None:
        raise ValueError("transpiler: no function found")
    from . import api
    n_paths = len(api.contracts(src_path))
    return {"target": target, "code": _target_stub(fn, target, n_paths),
            "proof": None, "verified": False,
            "counterexample": None,
            "note": "stub: full emission is specced behind the gramir seam"}
