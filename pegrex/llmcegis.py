"""
llmcegis

║  CEGIS with LLM proposers, FM rejecters.  The proposer — a template      
║  engine, a user callable, or an HTTP endpoint wrapper — only suggests    
║  repairs; every suggestion is verified by semantics.verify_patch before  
║  anything is accepted, and every refusal carries a concrete              
║  counterexample back into the next proposal round.                       

║  Division of labor (stated plainly): the LLM is a proposer, the engine   
║  remains the rejecter.  The prompt payload ships the counterexample as   
║  ground truth — hallucinated patches are refused with evidence, never    
║  trusted on authority.  Three-valued: exhaustion reports repaired=False  
║  with an honest final verdict; a proof that never came is not claimed."""

from __future__ import annotations

import ast
import json
import os
import re
import tempfile
import urllib.error
import urllib.parse
import urllib.request

from .cegis import repair as _cegis_repair
from .semantics import verify_patch


class LLMProposerError(ValueError):
    """Proposer unavailable, misconfigured, or non-conforming — loud refusal
    instead of inventing a candidate."""


# ---------------------------------------------------------------------------
# Executing candidate/before sources on counterexample inputs (sandbox-ish:
# importlib + first-top-level-def, mirroring chain._target_fn_name)
# ---------------------------------------------------------------------------

def _target_fn_name(src: str):
    tree = ast.parse(src)
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name
    return None


def _exec_result(src: str, inputs: dict):
    """fn(**inputs) for the first top-level def; None if unloadable."""
    import inspect
    import importlib.util
    name = _target_fn_name(src)
    if name is None:
        return None
    fd, path = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(src)
        spec = importlib.util.spec_from_file_location("cand_mod", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        fn = getattr(mod, name)
        try:
            params = set(inspect.signature(fn).parameters)
            kwargs = {k: v for k, v in inputs.items() if k in params}
        except (TypeError, ValueError):
            kwargs = dict(inputs)
        return fn(**kwargs)
    except Exception:
        return None
    finally:
        os.unlink(path)


def _const_spans(src: str, where=None):
    """[(lineno, col, end_lineno, end_col, value)] for int constants,
    optionally filtered to constants inside `where(node)` subtrees."""
    tree = ast.parse(src)
    hits = []
    if where is not None:
        keep = set()
        for node in ast.walk(tree):
            if where(node):
                for sub in ast.walk(node):
                    keep.add(id(sub))
        pred = lambda n: id(n) in keep
    else:
        pred = lambda n: True
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, int) \
                and not isinstance(node.value, bool) and pred(node):
            hits.append((node.lineno, node.col_offset, node.end_lineno,
                         node.end_col_offset, node.value))
    return sorted(set(hits))


def _splice(src: str, spans, index: int, new_text: str) -> str:
    """Replace the `index`-th span (1-based line/col coordinates) in src."""
    ln, co, eln, eco, _ = spans[index]
    lines = src.splitlines(keepends=True)
    if ln == eln:
        line = lines[ln - 1]
        lines[ln - 1] = line[:co] + new_text + line[eco:]
    else:
        lines[ln - 1] = lines[ln - 1][:co] + new_text
        for mid in range(ln, eln - 1):
            lines[mid] = ""
        lines[eln - 1] = lines[eln - 1][eco:]
    return "".join(lines)


def _parse_ok(src) -> bool:
    if not isinstance(src, str):
        return False
    try:
        ast.parse(src)
        return True
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return False


def _in_return_value(node) -> bool:
    """Is node part of a return statement's value (not a guard)?"""
    return isinstance(node, ast.Return) and node.value is not None


# ---------------------------------------------------------------------------
# TemplateProposer — real offline proposer
# ---------------------------------------------------------------------------

class TemplateProposer:
    """AST-aware repair templates driven by counterexample feedback.

    Strategies, in order; each returns a candidate source or None:
      1. constant adjustment — with failing input x* and differing outputs,
         nudge a mismatched return-expression constant by the observed
         output delta; the nudged candidate must agree with before on x*;
      2. branch-condition flip on a guard seen in the counterexample path;
      3. boundary off-by-one (k -> k+1, then k-1) on those guard constants.
    Every candidate is ast.parse-checked; an invalid splice falls through
    to the next strategy — syntactically invalid Python is never proposed.
    """

    def __init__(self, before_src: str):
        self.before_src = before_src
        self.last_candidate = None

    def __call__(self, feedback):
        if not feedback or not feedback.get("counterexample"):
            # round 0: probe — perturb the first return-expression constant
            cand = self._round0_probe()
            self.last_candidate = cand
            return cand
        cand = (self._constant_adjustment(feedback)
                or self._branch_flip(feedback)
                or self._off_by_one(feedback))
        self.last_candidate = cand
        return cand

    def _round0_probe(self):
        spans = _const_spans(self.before_src, _in_return_value)
        if not spans:
            return None
        cand = _splice(self.before_src, spans, 0, str(spans[0][4] + 1))
        return cand if _parse_ok(cand) else None

    def _constant_adjustment(self, feedback):
        cx = feedback["counterexample"]
        inputs = cx.get("inputs") or {}
        if not inputs:
            return None
        expected = _exec_result(self.before_src, inputs)
        base = self.last_candidate or self.before_src
        got = _exec_result(base, inputs)
        if expected is None or got is None:
            return None
        try:
            delta = expected - got
        except TypeError:
            return None
        if delta == 0:
            return None
        spans = _const_spans(base, _in_return_value)
        for i, (_ln, _co, _eln, _eco, k) in enumerate(spans):
            cand = _splice(base, spans, i, str(k + delta))
            if not _parse_ok(cand):
                continue
            if _exec_result(cand, inputs) == expected:
                return cand
        return None

    _FLIP = {"<": ">=", "<=": ">", ">": "<=", ">=": "<",
             "==": "!=", "!=": "=="}

    def _guards_of(self, src: str) -> list:
        """Source spans of comparison operators inside if-tests."""
        tree = ast.parse(src)
        spans = []
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                for sub in ast.walk(node.test):
                    if isinstance(sub, ast.Compare) and len(sub.ops) == 1:
                        op = sub.ops[0]
                        cls = type(op)
                        if cls in (ast.Lt, ast.LtE, ast.Gt, ast.GtE,
                                   ast.Eq, ast.NotEq):
                            spans.append((sub.lineno, sub.col_offset,
                                          sub.end_lineno, sub.end_col_offset,
                                          cls))
        return sorted(set(spans))

    def _branch_flip(self, feedback):
        base = self.last_candidate or self.before_src
        try:
            guards = self._guards_of(base)
        except SyntaxError:
            return None
        if not guards:
            return None
        for i, (_ln, _co, _eln, _eco, cls) in enumerate(guards):
            cand = _splice(base, guards, i,
                           self._FLIP[self._OPNAME[cls]])
            if _parse_ok(cand):
                return cand
        return None

    _OPNAME = {ast.Lt: "<", ast.LtE: "<=", ast.Gt: ">", ast.GtE: ">=",
               ast.Eq: "==", ast.NotEq: "!="}

    def _off_by_one(self, feedback):
        cx = feedback["counterexample"]
        path = cx.get("path") or []
        ks = sorted({int(m.group(0))
                     for c in path for m in re.finditer(r"-?\d+", str(c))})
        if not ks:
            return None
        base = self.last_candidate or self.before_src
        try:
            guards = self._guards_of(base)
        except SyntaxError:
            return None
        guard_consts = [s for s in _const_spans(base)
                        if any(s[0] == g[0] and s[1] >= g[1]
                               and s[2] <= g[2] for g in guards)]
        for (_ln, _co, _eln, _eco, k) in guard_consts:
            for k2 in (k + 1, k - 1):
                cand = self._replace_const(base, k, k2)
                if cand and _parse_ok(cand):
                    return cand
        return None

    def _replace_const(self, src: str, old: int, new: int):
        spans = _const_spans(src)
        for i, (_l, _c, _e, _ec, k) in enumerate(spans):
            if k == old:
                cand = _splice(src, spans, i, str(new))
                if _parse_ok(cand):
                    return cand
        return None


# ---------------------------------------------------------------------------
# HTTProposer — proposer that delegates suggestions to an HTTP endpoint
# ---------------------------------------------------------------------------

class HTTProposer:
    """POST {"before_src", "claim", "counterexample", "round"} as canonical
    JSON to an LLM endpoint; the response's "candidate_src" is the proposal.

    The prompt payload carries the counterexample as ground truth: the model
    proposes, it never certifies — pegrex remains the rejecter, so a
    hallucinated candidate is refused with evidence like any other.

    Endpoint resolution: explicit argument, else $PEGREX_LLM_ENDPOINT, else
    LLMProposerError — we refuse to hallucinate a proposer."""

    def __init__(self, endpoint=None, timeout=10, claim="equivalent"):
        self.endpoint = endpoint if endpoint is not None \
            else os.environ.get("PEGREX_LLM_ENDPOINT")
        self.timeout = timeout
        self.claim = claim
        self.round = 0
        self.before_src = ""

    def __call__(self, feedback):
        self.round += 1
        if not self.endpoint:
            raise LLMProposerError(
                "PEGREX_LLM_ENDPOINT not set — refusing to hallucinate "
                "a proposer")
        endpoint = urllib.parse.urlsplit(self.endpoint)
        if (endpoint.scheme not in {"http", "https"} or not endpoint.hostname
                or endpoint.username is not None or endpoint.password is not None):
            raise LLMProposerError(
                "LLM proposer endpoint must be an http(s) URL without embedded credentials")
        payload = {"before_src": self.before_src, "claim": self.claim,
                   "counterexample": (feedback or {}).get("counterexample"),
                   "round": self.round}
        body = json.dumps(payload, sort_keys=True).encode()
        req = urllib.request.Request(self.endpoint, data=body, headers={
            "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raise LLMProposerError(f"LLM proposer HTTP {e.code}: {e.reason}")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise LLMProposerError(f"LLM proposer unreachable: {e}")
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as e:
            raise LLMProposerError(f"LLM proposer non-JSON response: {e}")
        cand = data.get("candidate_src") if isinstance(data, dict) else None
        if not isinstance(cand, str):
            raise LLMProposerError(
                'LLM proposer response lacks "candidate_src"')
        return cand


# The CEGIS loop (pegrex/cegis.repair-compatible verify step)

def _resolve(proposer, before_src, claim):
    """-> (kind, propose_fn).  propose_fn(feedback)->source|None, where
    feedback is None on round 0, else {"counterexample": ...,
    "failing_paths": [...]}."""
    if proposer == "templates":
        return "templates", TemplateProposer(before_src)
    if isinstance(proposer, str):
        raise LLMProposerError(f"unknown proposer kind {proposer!r}")
    kind = "http" if isinstance(proposer, HTTProposer) \
        else getattr(proposer, "__name__", type(proposer).__name__)
    if hasattr(proposer, "before_src"):
        proposer.before_src = before_src
    if hasattr(proposer, "claim"):
        proposer.claim = claim
    return kind, proposer


def repair(before_src, claim="equivalent", proposer="templates", verifier=None,
           max_rounds=6) -> dict:
    """CEGIS: propose -> verify (semantics.verify_patch semantics) -> feed
    the counterexample + failing paths into the next round, until a real
    proof or the round budget.  Nothing is accepted without its verify_patch
    certificate; exhaustion returns repaired=False with an honest final
    verdict — a proof that never came is not claimed."""
    kind, propose_fn = _resolve(proposer, before_src, claim)
    history: list = []
    round_no = [0]
    last_verdict: dict = {"verified": False, "claim": claim,
                          "counterexample": None, "note": "no proposal "
                          "reached the verifier"}

    def _adapt(feedback):
        round_no[0] += 1
        payload = None if feedback is None else {
            "counterexample": feedback.get("counterexample"),
            "failing_paths": feedback.get("distinguishing", [])}
        cand = propose_fn(payload)
        history.append({"round": round_no[0],
                        "proposal": (cand or "").splitlines()[0][:80]
                        if cand else None,
                        "status": "pending"})
        return cand

    def _tracking_verify(before_path, patch_path, claim_):
        nonlocal last_verdict
        out = (verifier or verify_patch)(before_path, patch_path, claim_)
        last_verdict = dict(out)
        return out

    out = _cegis_repair(before_src, _adapt, claim=claim,
                        max_rounds=max_rounds,
                        verifier=_tracking_verify)
    status_map = {"verified": "verified", "refused": "refused",
                  "error": "invalid",   # unparseable/garbage proposal
                  "gave-up": "gave-up", "proposer-error": "proposer-error"}
    for i, entry in enumerate(out["trail"]):
        if i < len(history):
            history[i]["status"] = status_map.get(entry["status"],
                                                  entry["status"])
            if entry["status"] == "refused":
                history[i]["feedback"] = entry.get("feedback")
            elif entry["status"] == "error":
                history[i]["error"] = entry.get("error")
        else:      # safety: never lose a round
            history.append({"round": entry["round"],
                            "proposal": "", "status": entry["status"]})
    final = out["certificate"] if out["verified"] else last_verdict
    return {"repaired": bool(out["verified"]), "rounds": out["rounds"],
            "history": history, "final": final, "proposer": kind}
