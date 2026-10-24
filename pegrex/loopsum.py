"""
loopsum

║  Loop summaries instead of unrolling: candidate invariants are inferred   
║  Houdini-style (invariants.py) and discharged by entailment; termination  
║  is discharged by a ranking function (rank.py); counting loops get a      
║  closed form (loops.py).  A summary is only claimed when the engine can  
║  prove it -- otherwise the verdict names exactly what is missing."""

from __future__ import annotations

import ast
import re

from .invariants import _lhs_var, infer_invariants
from .ir import lower_condition
from .loops import closed_form, contract_closed_form, detect
from .rank import deltas_of, find_ranking

_DELTA = re.compile(r"^([A-Za-z_]\w*)\s*=\s*\1\s*([+-])\s*(\d+)$")
_ACC = re.compile(r"^([A-Za-z_]\w*)\s*=\s*(?:\1\s*\+\s*([A-Za-z_]\w*)"
                  r"|([A-Za-z_]\w*)\s*\+\s*\1)$")
_GUARD = re.compile(r"^([A-Za-z_]\w*)\s*(<=|<|>=|>)\s*([A-Za-z_]\w*|-?\d+)$")


class LoopSumError(ValueError):
    """Refusal: the loop leaves the summarizable fragment."""


def _loop_parts(src: str, fn_name: str | None):
    """Extract (fn, pre-loop int inits, guard text, body assignment texts)."""
    tree = ast.parse(src)
    fns = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
    if fn_name:
        fns = [f for f in fns if f.name == fn_name]
    if len(fns) != 1:
        raise LoopSumError(
            f"expected exactly one function"
            + (f" named {fn_name!r}" if fn_name else "") + f", found {len(fns)}")
    fn = fns[0]
    whiles = [s for s in fn.body if isinstance(s, ast.While)]
    if not whiles:
        raise LoopSumError(f"{fn.name}: no while loop to summarize")
    if len(whiles) > 1:
        raise LoopSumError(f"{fn.name}: multiple loops -- summarize one at a time")
    loop = whiles[0]
    guard = ast.unparse(loop.test)
    try:
        from .refine import _norm_constraint
        from .linsolve import parse_atom
        parse_atom(_norm_constraint(guard))     # LinearError outside QF_LIA
    except Exception as e:
        raise LoopSumError(
            f"{fn.name}: loop guard {guard!r} outside the linear fragment: {e}")
    inits, body = {}, []
    for s in fn.body[:fn.body.index(loop)]:
        if isinstance(s, ast.Assign) and len(s.targets) == 1 and \
                isinstance(s.targets[0], ast.Name) and \
                isinstance(s.value, ast.Constant) and isinstance(s.value.value, int):
            inits[s.targets[0].id] = s.value.value
        else:
            raise LoopSumError(
                f"{fn.name}: pre-loop statement {ast.unparse(s)!r} is not a "
                "constant initialization -- outside the fragment")
    for s in loop.body:
        if isinstance(s, ast.Assign) and len(s.targets) == 1 and \
                isinstance(s.targets[0], ast.Name):
            body.append(ast.unparse(s))
        else:
            raise LoopSumError(
                f"{fn.name}: loop body statement {ast.unparse(s)!r} is not a "
                "simple assignment -- outside the fragment")
    return fn, inits, guard, body


def _classify(body: list[str]):
    """Split body assignments into counter deltas and accumulators."""
    deltas, accs = {}, []
    for b in body:
        t = b.replace(" ", "")
        if (m := _DELTA.match(t)):
            k = int(m.group(3)) * (1 if m.group(2) == "+" else -1)
            deltas[m.group(1)] = k
        elif (m := _ACC.match(b)):
            accs.append((m.group(1), m.group(2) or m.group(3)))
        else:
            raise LoopSumError(
                f"assignment {b!r} is neither a constant-delta counter nor a "
                "linear accumulator -- outside the fragment")
    return deltas, accs


class _StepCap(Exception):
    """Evidence run exceeded the iteration cap -- non-termination evidence,
    exactly what a missing ranking function predicts."""


def _cross_check(src: str, fn, invariant: list[str], samples,
                 closed_expr: str | None = None,
                 bound_var: str | None = None, step_cap: int = 100_000) -> list:
    """Concrete-execution evidence: the discharged invariant must hold at
    every iteration of sampled real runs, and the closed form (when
    available) must equal the real return value. Runs are step-capped: a
    loop the ranking could not prove may simply not terminate, and that is
    recorded as evidence, never hung on. Evidence, not proof -- but it is
    exactly the check that caught a wrong closed form standing unchallenged
    in m7 (Gauss factor of 2)."""
    import itertools
    tree = ast.parse(src)
    fn_node = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                   and n.name == fn.name)
    loop = next(s for s in fn_node.body if isinstance(s, ast.While))
    fn_indent = " " * fn_node.body[0].col_offset
    loop_indent = " " * loop.body[0].col_offset
    lines = src.splitlines()
    # instrument body (insert at loop body start, reverse order keeps linenos)
    inject = [f"{loop_indent}__steps += 1",
              f"{loop_indent}if __steps > {step_cap}: raise _StepCap()"]
    inject += [f"{loop_indent}assert _holds({inv!r}, locals()), {inv!r}"
               for inv in invariant]
    lines[loop.lineno:loop.lineno] = []  # placeholder, keep indexes stable
    lines[loop.lineno - 1 + 1:loop.lineno - 1 + 1] = []
    body_at = loop.body[0].lineno - 1
    lines[body_at:body_at] = inject
    loop_line = loop.lineno - 1
    lines[loop_line:loop_line] = [f"{fn_indent}__steps = 0"]
    instr_src = "\n".join(lines)

    ns: dict = {"_holds": _holds, "_StepCap": _StepCap}
    exec(instr_src, ns)  # operator-supplied source, CLI-style
    fn_obj = ns[fn.name]
    params = [a.arg for a in fn.args.args]
    checked = nonterminating = 0
    for combo in itertools.islice(itertools.product(*samples), 6):
        call = dict(zip(params, combo))
        try:
            got = fn_obj(**call)
        except _StepCap:
            nonterminating += 1
            continue
        if closed_expr and bound_var is not None and \
                call.get(bound_var, 0) >= 0:
            want = eval(closed_expr, {bound_var: call[bound_var]})
            assert got == want, \
                f"closed form {closed_expr!r} != {got} at {bound_var}={call[bound_var]}"
        checked += 1
    return [{"samples_checked": checked, "violations": 0,
             "nonterminating": nonterminating,
             "closed_form_checked": closed_expr is not None}]


def _holds(inv: str, env: dict) -> bool:
    m = _GUARD.match(inv.replace(" ", ""))
    if not m:
        return True  # non-simple invariant: evidence n/a
    a = env.get(m.group(1), 0)
    b = env.get(m.group(3)) if not m.group(3).lstrip("-").isdigit() \
        else int(m.group(3))
    if b is None:
        return True
    return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[m.group(2)]


def summarize(src: str, fn_name: str | None = None, lb=None,
              evidence: bool = True) -> dict:
    """One Python while-loop -> a proven summary, or an honest refusal.

    verdicts: "proved" (invariant discharged and ranking discharged),
    "summary-only" (invariant discharged; termination unproven -- says so),
    "refused" (nothing provable; reason names the gap)."""
    fn, inits, guard, body = _loop_parts(src, fn_name)
    deltas, accs = _classify(body)
    init_atoms = [f"{v} = {k}" for v, k in inits.items()]

    inferred = infer_invariants(guard, deltas, init_atoms, lb=lb)
    # invariants.infer keeps facts about vars with no delta info as "sound
    # entry facts" -- but an entry fact about a mutated accumulator is not an
    # invariant (its consecution was never checked). Keep only invariants on
    # delta-counters (consecution discharged) or unmutated vars;
    # accumulator invariants are dropped and named, never silently kept.
    mutated = set(deltas) | {a for a, _ in accs}
    dropped_no_consec = [c for c in inferred["invariants"]
                         if _lhs_var(c) in mutated and _lhs_var(c) not in deltas]
    invariant = [c for c in inferred["invariants"]
                 if c not in dropped_no_consec]
    ranking = find_ranking(guard, deltas, lb=lb) if deltas else None

    closed = None
    cl = detect(body, inits)
    gm = _GUARD.match(guard.replace(" ", ""))
    if cl and gm and gm.group(1) == cl.index and gm.group(2) in ("<=", "<"):
        bound = gm.group(3)
        if gm.group(2) == "<":
            # i < k iterates to k-1: shift the bound before summarizing
            bound = (str(int(bound) - 1) if bound.lstrip("-").isdigit()
                     else f"({bound} - 1)")
        closed = {"accumulator": cl.accum,
                  **contract_closed_form(cl, bound)}

    if invariant and ranking:
        verdict, reason = "proved", None
    elif invariant:
        verdict = "summary-only"
        reason = ("invariant discharged by entailment; no ranking function "
                  "found -- termination unproven, named not hidden")
    else:
        verdict = "refused"
        reason = ("no invariant survived initiation+consecution; "
                  f"dropped at initiation: {inferred['dropped_at_initiation']}")

    out = {"function": fn.name, "guard": guard, "deltas": deltas,
           "accumulators": [a for a, _ in accs], "invariant": invariant,
           "ranking": ranking, "closed_form": closed,
           "verdict": verdict}
    if dropped_no_consec:
        out["dropped_no_consecution"] = dropped_no_consec
    if reason:
        out["reason"] = reason
    if evidence and invariant:
        params = [a.arg for a in fn.args.args]
        bound_var = gm.group(3) if gm else None
        closed_expr = closed["result"] if (
            closed and bound_var and not bound_var.lstrip("-").isdigit()
            and bound_var in params) else None
        out["evidence"] = _cross_check(src, fn, invariant,
                                       samples=[range(-2, 5)] * len(params),
                                       closed_expr=closed_expr,
                                       bound_var=bound_var)
    return out
