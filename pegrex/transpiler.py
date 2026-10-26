"""Contract-guided transpilation with explicit candidate and proof states.

Only independently verified Python emission is published as target code.
Unsupported targets and unverified candidates remain UNKNOWN; the API never
returns a compilable placeholder as if it were a translation.
"""
from __future__ import annotations

import ast
import json
import os
from pathlib import Path
import tempfile


def _proof_state(proof):
    counterexample = (proof or {}).get("counterexample") or {}
    if (proof or {}).get("verified") is True:
        return "proved"
    if counterexample.get("confirmed") is True:
        return "refuted"
    return "unknown"


def transpile(source_path: str, target_lang: str,
              out_path: str | None = None) -> dict:
    """Return the historical bundle shape with production trust metadata.

    ``target_stub`` is retained as a compatibility key, but it now contains
    verified code or null. Bounded path enumeration fails closed on overflow.
    """
    from pegrex.cfg import CFGBuilder
    from pegrex.paths import PathEnumerator
    from pegrex.languages import detect_language, get_contract_frontend

    src = Path(source_path).read_text(encoding="utf-8")
    language = detect_language(source_path)
    if language is None:
        raise ValueError(f"transpiler: unknown source language for {source_path!r}")
    parse, tags, _ = get_contract_frontend(language)()
    body = parse(src)
    cfg = CFGBuilder(tags).build(body)
    enumeration = PathEnumerator(
        cfg, unroll=2, max_paths=10_000, timeout_ms=5_000).enumerate_bounded()
    if not enumeration.complete:
        raise RuntimeError("transpiler path enumeration incomplete: "
                           + "; ".join(enumeration.unknowns))
    result = transpile_certified(source_path, target=target_lang)
    bundle = {
        "source": source_path,
        "target_lang": target_lang,
        "paths": [list(path) for path in enumeration.paths],
        "target_stub": result.get("code"),
        "candidate_code": result.get("candidate_code"),
        "proof": result.get("proof") or {
            "kind": "unknown",
            "paths": len(enumeration.paths),
            "method": "no supported verified emission path",
        },
        "status": result.get("status", "unknown"),
        "unknowns": list(result.get("unknowns", [])),
    }
    if out_path:
        Path(out_path).write_text(
            json.dumps(bundle, indent=1, sort_keys=True), encoding="utf-8")
    return bundle


def certified_python_transpile(src_path: str) -> dict:
    """Emit Python through the contract IR and independently reanalyze it.

    The generated candidate remains available for diagnostics, but ``code`` is
    populated only when the semantic verifier proves the requested equivalence.
    """
    from . import api
    from .emitter import emit_python
    from .semantics import verify_patch

    contracts = api.contracts(src_path)
    source = Path(src_path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(src_path))
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)]
    if not functions:
        raise ValueError("transpiler: no function to transpile")
    function = functions[0]
    parameters = [argument.arg for argument in function.args.args]
    candidate = emit_python(function.name, parameters, contracts)
    descriptor, output = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(candidate)
        proof = verify_patch(src_path, output)
    finally:
        if os.path.exists(output):
            os.unlink(output)
    status = _proof_state(proof)
    unknowns = []
    if status == "unknown":
        unknowns.append((proof or {}).get("note")
                        or "semantic verification did not prove equivalence")
    return {
        "target": "python",
        "code": candidate if status == "proved" else None,
        "candidate_code": candidate,
        "proof": proof,
        "status": status,
        "verified": status == "proved",
        "counterexample": (proof or {}).get("counterexample"),
        "unknowns": unknowns,
    }


def transpile_certified(src_path: str, target: str = "python") -> dict:
    """Transpile only through a registered, independently checked emitter."""
    from .languages import normalize_language

    normalized = normalize_language(target)
    if normalized == "python":
        return certified_python_transpile(src_path)
    reason = (f"no production verified emitter is registered for target {target!r}"
              if normalized is None else
              f"verified {normalized} emission is not implemented for this source path")
    return {
        "target": target,
        "code": None,
        "candidate_code": None,
        "proof": None,
        "status": "unknown",
        "verified": False,
        "counterexample": None,
        "unknowns": [reason],
        "note": reason,
    }
