"""
incverify

║  Incremental verify_patch: per-function AST-hash keys. Unchanged          
║  functions are structurally identical -> proof is free (O(1)); only the   
║  diff goes through the engine. Verdicts are cached; a corrupt cache is    
║  rebuilt loudly, never trusted silently."""

from __future__ import annotations

import ast
import hashlib
import json
import pathlib
import tempfile

from .cache import AnalysisCache
from .semantics import verify_patch

_ANALYZERS = ("verify-patch",)


class IncverifyError(ValueError):
    """Refusal: the inputs or the cache cannot be trusted."""


def _parse(src: str, path: str) -> ast.Module:
    try:
        return ast.parse(src)
    except SyntaxError as e:
        raise IncverifyError(f"cannot parse {path}: {e}") from e


def _functions(tree: ast.Module, src: str) -> dict:
    """{name: {"hash": sha256(ast)[:16], "src": segment}} for top-level defs."""
    out = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            out[node.name] = {
                "hash": hashlib.sha256(
                    ast.dump(node, include_attributes=False).encode()
                ).hexdigest()[:16],
                "src": ast.get_source_segment(src, node),
            }
    return out


def verify_patch_incremental(before_path, after_path, claim: str = "equivalent",
                             cache: AnalysisCache | None = None) -> dict:
    """verify_patch that only pays for the diff.

    Per top-level function:
      - identical AST-hash on both sides      -> proof is structural: free
      - hash pair seen in the verdict cache   -> reused
      - changed / new                         -> engine verify_patch on the
                                                 extracted function sources
      - removed                               -> counterexample (a deleted
                                                 function is a behavioral
                                                 change, never silent)
    """

    for p in (before_path, after_path):
        if not pathlib.Path(p).exists():
            raise IncverifyError(f"no such file: {p}")
    cache = cache if cache is not None else AnalysisCache(".pegrex-cache")
    before_src = pathlib.Path(before_path).read_text(encoding="utf-8")
    after_src = pathlib.Path(after_path).read_text(encoding="utf-8")
    before = _functions(_parse(before_src, str(before_path)), before_src)
    after = _functions(_parse(after_src, str(after_path)), after_src)

    per_function, distinguishing = {}, []
    reused = reverified = cache_hits = cache_rebuilt = 0
    counterexample = None
    ok = True

    for name, b in before.items():
        if name not in after:
            per_function[name] = {"verdict": "removed", "verified": False}
            distinguishing.append({"function": name, "change": "removed"})
            ok = False
            continue
        a = after[name]
        if a["hash"] == b["hash"]:
            reused += 1
            per_function[name] = {"verdict": "identical", "verified": True}
            continue
        key_src = f"{name}:{b['hash']}->{a['hash']}"
        try:
            cached = cache.get(key_src, _ANALYZERS)
        except (json.JSONDecodeError, UnicodeDecodeError):
            cache_rebuilt += 1
            cached = None
        if cached is not None and cached.get("verified") is True:
            cache_hits += 1
            per_function[name] = {"verdict": "cached", "verified": True}
            continue
        reverified += 1
        with tempfile.TemporaryDirectory() as td:
            fb = pathlib.Path(td) / f"before_{name}.py"
            fa = pathlib.Path(td) / f"after_{name}.py"
            fb.write_text(b["src"] + "\n", encoding="utf-8")
            fa.write_text(a["src"] + "\n", encoding="utf-8")
            v = verify_patch(str(fb), str(fa), claim)
        if v.get("verified"):
            per_function[name] = {"verdict": "engine", "verified": True}
            cache.put(key_src, _ANALYZERS, {"verified": True})
        else:
            per_function[name] = {"verdict": "engine", "verified": False}
            distinguishing.append({"function": name,
                                   "distinguishing": v.get("distinguishing", [])})
            if counterexample is None:
                counterexample = v.get("counterexample")
            ok = False

    for name in after:
        if name not in before:
            per_function[name] = {"verdict": "added", "verified": True}
            distinguishing.append({"function": name, "change": "added"})

    return {
        "verdict": "proved" if ok else "counterexample",
        "claim": claim,
        "reused": reused,
        "cache_hits": cache_hits,
        "cache_rebuilt": cache_rebuilt,
        "reverified": reverified,
        "per_function": per_function,
        "counterexample": counterexample,
        "distinguishing": distinguishing,
    }
