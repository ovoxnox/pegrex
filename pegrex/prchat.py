"""
prchat — natural-language contract chat for PR review 

║  A reviewer asks a question in English ("does this reject negative      
║  balances?"); the question is turned into a candidate invariant (an    
║  enumerated-template proposer, same never-invent discipline as m95's    
║  nlspec.propose), checked against the function's real path contracts, 
║  and the answer is rendered as a PR-comment-style markdown       
║  reply: proven (naming the discharging paths), refuted (with a  
║  concrete counterexample input), or honestly unknown/unrecognized --   
║  never a guess dressed up as an answer.  

║  No network/API calls: this renders the comment text a bot would post; 
║  actually posting it is the caller's job (same offline-honesty seam as 
║  slsa.publish_sigstore -- this module never pretends to reach GitHub)."""

from __future__ import annotations

import re

from . import api
from .ir import lower_condition
from .linsolve import LinearBackend, atoms_of, parse_atom
from .nlspec import check, propose
from .refine import _neg, _norm_constraint

_QUESTION_TEMPLATES = [
    (r"(?:is|does)\s+(\w+)\s+(?:always\s+)?(?:non-negative|never negative)\??",
     lambda m: f"{m.group(1)} >= 0"),
    (r"(?:is|does)\s+(\w+)\s+(?:always\s+)?(?:non-positive|never positive)\??",
     lambda m: f"{m.group(1)} <= 0"),
    (r"(?:is|does)\s+(\w+)\s+(?:always\s+)?(?:positive|greater than zero)\??",
     lambda m: f"{m.group(1)} > 0"),
    (r"(?:is|does)\s+the result\s+(?:always\s+)?(?:non-negative|at least 0)\??",
     lambda m: "result >= 0"),
    (r"does\s+(?:this|it)\s+reject\s+negative\s+(\w+)\??",
     lambda m: f"{m.group(1)} >= 0"),
    (r"(?:does|can)\s+(\w+)\s+(?:ever\s+)?exceed\s+(\w+)\??",
     lambda m: f"{m.group(1)} <= {m.group(2)}"),
    (r"(?:is|does)\s+(\w+)\s+(?:always\s+)?at most\s+(\w+|[+-]?\d+)\??",
     lambda m: f"{m.group(1)} <= {m.group(2)}"),
    (r"is\s+(?:the\s+)?result\s+(?:always\s+)?at least\s+(\w+)\??",
     lambda m: f"result >= {m.group(1)}"),
]


def propose_from_question(question: str) -> list:
    """Question-phrased proposer: enumerated templates only, exactly like
    nlspec.propose -- an unrecognized phrasing yields [], never an
    invented guess. Falls through to nlspec.propose itself too, so an
    already-declarative question ("n is non-negative?") still works."""
    out = []
    for rx, fn in _QUESTION_TEMPLATES:
        for m in re.finditer(rx, question, re.I):
            cand = fn(m)
            if cand not in out:
                out.append(cand)
    out += [c for c in propose(question) if c not in out]
    return out


def _paths_and_models(src_path, lb):
    """Same per-path atom extraction nlspec.check uses internally --
    duplicated here (not imported) because nlspec.check does not expose
    the per-path models, and this module needs them to produce a concrete
    counterexample, not just a status string."""
    paths = []
    for cs, res in api.contracts(src_path):
        atoms = []
        for c in cs:
            n = _norm_constraint(str(c))
            try:
                parse_atom(n)
                atoms.append(n)
            except Exception:
                pass
        paths.append((atoms, str(res)))
    return paths


def _counterexample(src_path, candidate, lb=None):
    """The concrete input that refutes `candidate` on the path where it
    was dropped, or None if it was not dropped / no witness could be
    constructed (refuse to fabricate one)."""
    lb = lb or LinearBackend()
    for atoms, res in _paths_and_models(src_path, lb):
        if not atoms:
            continue
        sub = re.sub(r"\bresult\b", f"({res})", candidate) \
            if "result" in candidate else candidate
        try:
            es = lower_condition(sub)
        except Exception:
            continue
        model = lb.learn(atoms)
        if not model.feasible():
            continue
        try:
            if lb.entails(model, _neg(es)):
                vals = model.model()
                if vals:
                    return {"inputs": vals, "path_result": res}
        except Exception:
            continue
    return None


def answer_question(src_path, question, lb=None) -> dict:
    """Ask one English question about a function's real contracts.

    Returns {"status": ..., "question": ..., "candidates": [...]} where
    each candidate carries its own proven/dropped/unknown verdict (and a
    counterexample for "dropped"). status == "no-template" means the
    question's phrasing matched no enumerated template -- refused, not
    guessed; rephrase as a direct claim."""
    lb = lb or LinearBackend()
    candidates = propose_from_question(question)
    if not candidates:
        return {"status": "no-template", "question": question,
                "candidates": []}
    verdicts = check(src_path, candidates=candidates, lb=lb)
    for v in verdicts:
        if v["status"] == "dropped":
            v["counterexample"] = _counterexample(src_path, v["candidate"], lb)
    return {"status": "answered", "question": question, "candidates": verdicts}


def render_pr_comment(answer: dict) -> str:
    """Render answer_question()'s result as PR-comment-style markdown --
    the text a review bot would post, not an actual network post."""
    q = answer["question"]
    if answer["status"] == "no-template":
        return (f"> **Q:** {q}\n\n"
                f"I don't have a template for that phrasing yet -- I won't "
                f"guess. Try a direct claim like \"the result is always "
                f"non-negative\" or \"x must not exceed y\".")
    lines = [f"> **Q:** {q}", ""]
    for v in answer["candidates"]:
        cand = v["candidate"]
        if v["status"] == "proven":
            lines.append(f"- \u2705 **Proven:** `{cand}` holds on every path.")
        elif v["status"] == "dropped":
            ce = v.get("counterexample")
            if ce:
                lines.append(
                    f"- \u274c **Refuted:** `{cand}` fails with "
                    f"`{ce['inputs']}` (path result `{ce['path_result']}`).")
            else:
                lines.append(f"- \u274c **Refuted:** `{cand}` fails on some path.")
        else:
            lines.append(f"- \u2753 **Unknown:** `{cand}` is outside the "
                         f"provable fragment -- not claimed either way.")
    return "\n".join(lines)
