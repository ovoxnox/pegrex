"""
cegis — counterexample-guided repair

The LLM/agent proposes; pegrex certifies or refuses with the failing
path and CONCRETE inputs as feedback; the loop repeats until verified
or the round budget is exhausted. The proposer is a pluggable
function -- mini_llm, an external model, or a scripted oracle.
Nothing is trusted: every accepted patch carries its verify_patch
certificate; every refusal carries a counterexample."""

from __future__ import annotations

import ast
import os
import tempfile

from .semantics import verify_patch


def repair(before_src, propose_fn, claim="equivalent", max_rounds=4,
           verifier=None) -> dict:
    """CEGIS loop.

    propose_fn(feedback) -> patch source string or None to give up.
    feedback: None on round 0; afterwards the previous refusal:
              {"counterexample": {...}, "distinguishing": [...]}.
    Returns the full trail -- every round with its verdict or error."""
    tmp = tempfile.mkdtemp()
    before_path = os.path.join(tmp, "before.py")
    open(before_path, "w", encoding="utf-8").write(before_src)
    trail = []
    feedback = None
    for rnd in range(1, max_rounds + 1):
        try:
            proposal = propose_fn(feedback)
        except Exception as e:
            trail.append({"round": rnd, "status": "proposer-error",
                          "error": f"{type(e).__name__}: {e}"[:200]})
            continue
        if proposal is None:
            trail.append({"round": rnd, "status": "gave-up"})
            break
        try:
            if not isinstance(proposal, str):
                raise TypeError("proposal must be Python source text")
            ast.parse(proposal)
        except (SyntaxError, ValueError, TypeError, MemoryError, RecursionError) as e:
            # Candidate validity is a Python property, not a property of whichever
            # optional parser backend happens to be installed.
            trail.append({"round": rnd, "status": "error",
                          "error": f"{type(e).__name__}: {e}"[:200],
                          "feedback": feedback})
            continue
        patch_path = os.path.join(tmp, f"patch{rnd}.py")
        open(patch_path, "w", encoding="utf-8").write(proposal)
        try:
            check = verifier or verify_patch
            out = check(before_path, patch_path, claim)
            out.setdefault("verified", False)
            out.setdefault("counterexample", None)
            out.setdefault("distinguishing", [])
        except Exception as e:
            trail.append({"round": rnd, "status": "error",
                          "error": f"{type(e).__name__}: {e}"[:200],
                          "feedback": feedback})
            continue
        if out["verified"]:
            trail.append({"round": rnd, "status": "verified",
                          "certificate": {"claim": claim,
                                          "counterexample": None}})
            return {"verified": True, "rounds": rnd, "trail": trail,
                    "patch": proposal, "certificate": out}
        feedback = {"counterexample": out.get("counterexample"),
                    "distinguishing": out.get("distinguishing", [])}
        trail.append({"round": rnd, "status": "refused", "feedback": feedback})
    return {"verified": False, "rounds": len(trail), "trail": trail,
            "certificate": None}
