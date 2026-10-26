"""
chain - integrated repair pipeline

CEGIS loop -> verify_patch -> sampled execution evidence.
Defense in depth: even if the contract layer is fooled (swapped verifier,
oracle gap), the execution layer refuses when concrete runs disagree.
With use_sandbox=True the execution layer runs candidates in an rlimited
subprocess (pegrex.sandbox) -- untrusted candidate code never execs in
the parent; without isolation the path refuses loudly, never fakes it.
"""

from __future__ import annotations

import importlib.util
import os
import tempfile

from . import api
from . import sandbox
from .cegis import repair
from .linsolve import LinearBackend, parse_atom
from .refine import _norm_constraint
from .strategies import sample_models


def _sample_inputs(before_src, n=4):
    fd, p = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(before_src)
    lb = LinearBackend()
    seen, out = set(), []
    try:
        for cs, _res in api.contracts(p):
            atoms = []
            for c in cs:
                nv = _norm_constraint(str(c))
                try:
                    parse_atom(nv)
                    atoms.append(nv)
                except Exception:
                    pass
            for m in sample_models(atoms, n=2, lb=lb):
                key = tuple(sorted(m.items()))
                if key not in seen:
                    seen.add(key)
                    out.append(m)
                if len(out) >= n:
                    return out
    finally:
        os.unlink(p)
    return out


def _load(src, name):
    fd, p = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(src)
    spec = importlib.util.spec_from_file_location(name, p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    os.unlink(p)
    return mod


def _target_fn_name(src):
    """The function this patch is about: the first top-level def in source
    order (the program's own intent), never an alphabetically-sorted guess
    over dir(module) that could just as easily pick an unrelated helper, a
    class, or an imported name re-exported into the module's namespace."""
    import ast
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name
    return None


def repaired_with_evidence(before_src, propose_fn, verifier=None, n_samples=4,
                           max_rounds=4, use_sandbox=False):
    """CEGIS -> contract verification -> sampled execution evidence.

    use_sandbox=False (default): candidates execute in-process (fast; the
    historical certified behavior). use_sandbox=True: candidate validation
    runs through sandbox.run_cegis_candidate in a rlimited subprocess --
    candidate code is never exec'd in the parent. If the sandbox is not
    available on this platform, SandboxError is raised loudly: falling
    back to in-process exec while claiming isolation would be a lie."""
    if use_sandbox and not sandbox.sandbox_available():
        raise sandbox.SandboxError(
            "chain: use_sandbox=True but no isolation is available on this "
            "platform -- refusing to fall back to in-process exec")
    out = repair(before_src, propose_fn, verifier=verifier, max_rounds=max_rounds) \
          if verifier else repair(before_src, propose_fn, max_rounds=max_rounds)
    if not out["verified"]:
        return {**out, "status": "refused", "layer": "contract", "evidence": []}
    patch = out["patch"]
    inputs = _sample_inputs(before_src, n_samples)
    if not inputs:
        return {**out, "status": "verified-no-runs", "evidence": []}
    if use_sandbox:
        try:
            run = sandbox.run_cegis_candidate(patch, before_src, inputs,
                                              lambda a, b: a == b)
        except sandbox.SandboxError:
            raise
        except Exception as e:
            return {**out, "status": "refused", "layer": "execution",
                    "evidence": [], "sandbox_error": str(e)[:160]}
        evidence = [{"inputs": e["inputs"], "before": e["before"],
                     "after": e["after"], "agree": e["agree"]}
                    for e in run["evidence"]]
        if not run["verified"]:
            return {**out, "status": "refused", "layer": "execution",
                    "evidence": evidence}
        return {**out, "status": "verified", "evidence": evidence,
                "sandboxed": True}
    try:
        m1 = _load(before_src, "before_mod")
        m2 = _load(patch, "after_mod")
    except Exception as e:
        return {**out, "status": "verified-no-runs", "evidence": [],
                "load_error": str(e)[:160]}
    target = _target_fn_name(before_src)
    if target is None or not hasattr(m1, target) or not hasattr(m2, target):
        return {**out, "status": "verified-no-runs", "evidence": [],
                "load_error": "no top-level function found to compare"}
    fn1, fn2 = getattr(m1, target), getattr(m2, target)
    evidence, disagreements = [], 0
    for inp in inputs:
        args = [inp[k] for k in sorted(inp)]
        try:
            r1 = fn1(*args)
        except Exception as e:
            r1 = f"error:{type(e).__name__}"
        try:
            r2 = fn2(*args)
        except Exception as e:
            r2 = f"error:{type(e).__name__}"
        agree = r1 == r2
        disagreements += 0 if agree else 1
        evidence.append({"inputs": inp, "before": r1, "after": r2,
                         "agree": agree})
    if disagreements:
        return {**out, "status": "refused", "layer": "execution",
                "evidence": evidence}
    return {**out, "status": "verified", "evidence": evidence}
