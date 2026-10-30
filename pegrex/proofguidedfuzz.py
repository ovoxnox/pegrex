"""Proof-guided input candidates from simple unresolved path predicates."""
from __future__ import annotations
import hashlib, json, re
SCHEMA = "pegrex.proof-guided-fuzz.v1"
_ATOM = re.compile(r"^\s*([A-Za-z_]\w*)\s*(==|!=|<=|>=|<|>)\s*(-?\d+)\s*$")

def candidates_from_conditions(conditions, *, max_candidates=256, radius=2):
    """Generate bounded integer candidates for simple x op integer conditions.

    This is candidate generation only; generated inputs are not counterexamples
    until a concrete execution and independent oracle confirm them.
    """
    out, seen = [], set()
    for condition in conditions:
        if len(out) >= max_candidates: break
        if not isinstance(condition, str): continue
        match = _ATOM.match(condition)
        if not match: continue
        name, op, raw = match.groups(); bound = int(raw)
        vals = {bound}
        if op in ("<", "<="): vals.update(range(bound-radius, bound+radius+1))
        elif op in (">", ">="): vals.update(range(bound-radius, bound+radius+1))
        elif op in ("==", "!="): vals.update((bound-1, bound+1))
        for val in sorted(vals):
            item = {name: val}
            key = json.dumps(item, sort_keys=True)
            if key not in seen:
                seen.add(key); out.append({"input": item, "derived_from": condition, "status": "candidate"})
                if len(out) >= max_candidates: break
    return {"schema": SCHEMA, "candidates": out, "confirmed_counterexamples": [],
            "warning": "Candidates require concrete execution and independent oracle validation"}

def confirm_counterexample(candidate, *, execute, oracle, regression_store=None):
    """Only promote an input when execution and an independent oracle both agree."""
    try:
        actual = execute(candidate["input"])
        expected = oracle(candidate["input"])
    except Exception as exc:
        return {"status": "unknown", "reason": type(exc).__name__}
    if actual == expected:
        return {"status": "not-counterexample", "actual": actual}
    record = {"input": candidate["input"], "actual": actual, "expected": expected,
              "condition": candidate.get("derived_from"), "status": "confirmed"}
    record["id"] = hashlib.sha256(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()
    if regression_store is not None:
        regression_store(record)
    return record
