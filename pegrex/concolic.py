"""
concolic — concolic execution

Run the real code under sys.settrace; branch predicates come from the 
AST (exact condition text); each run yields its path constraints.

Branch flipping: prefix constraints + negated target solved by the 
engine -> a concrete new input. Divergence between the symbolic 
expectation and the re-run trace is reported, never smoothed over."""

from __future__ import annotations

import ast
import inspect
import sys

from .ir import lower_condition
from .linsolve import LinearBackend, atoms_of
from .refine import _neg

DEFAULT_LB = LinearBackend()


def _if_map(fn, source=None) -> dict:
    """{lineno: condition-source} for every If/While test (AST-exact text).
    While guards are included -- a loop's test is re-evaluated (and traced)
    once per iteration, so it is a branch just like an If's test.

    inspect.getsource(fn) returns just the function's own snippet, whose
    AST line numbers start at 1 -- but frame.f_lineno during the real run
    reports ABSOLUTE line numbers in the source file. Without the offset
    below, the two only coincide when fn happens to start at line 1 (e.g.
    exec()'d test fixtures); for any real function living later in a real
    file, no branch would ever match and tracing would silently see none."""
    offset = 0
    if source is None:
        try:
            lines, start = inspect.getsourcelines(fn)
            source = "".join(lines)
            offset = start - 1
        except (OSError, TypeError) as e:
            raise ValueError(
                "concolic: no source available -- pass source=<str>") from e
    tree = ast.parse(source)
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.If, ast.While)):
            out[node.lineno + offset] = ast.unparse(node.test)
    return out


def trace_fn(fn, *args, source=None, lb=None, **kwargs) -> dict:
    """Concrete run + collected branch observations.

    branches: [(lineno, condition_text, truth)] in execution order.
    constraints: sym atoms of the taken path (linear fragment only).
    args/kwargs: the concrete call that produced this run -- kept so a
    later flip() can fall back to these concrete values for parameters
    the solver leaves unconstrained (see flip_and_verify)."""
    ifs = _if_map(fn, source)
    events = []

    def tracer(frame, event, arg):
        if event == "line" and frame.f_code is fn.__code__:
            ln = frame.f_lineno
            if ln in ifs:
                expr = ifs[ln]
                try:
                    truth = bool(eval(expr, {}, dict(frame.f_locals)))
                except Exception:
                    truth = None # condition outside evaluable fragment
                events.append((ln, expr, truth))
        return tracer

    sys.settrace(tracer)
    try:
        result = fn(*args, **kwargs)
    finally:
        sys.settrace(None)

    atoms = []
    dropped = 0
    for ln, expr, truth in events:
        if truth is None:
            dropped += 1
            continue
        try:
            cond = lower_condition(expr)
            atoms += atoms_of(cond if truth else _neg(cond))
        except Exception:
            dropped += 1
    return {"result": result, "branches": events,
            "constraints": atoms, "opaque_branches": dropped,
            "args": args, "kwargs": kwargs}


def flip(fn, run, branch_index, lb=None) -> dict:
    """Solve for an input that takes the opposite outcome at branch_index.

    Prefix = constraints of branches before the target (as observed);
    target added in negated form. Infeasible or unmodelable flips are
    reported honestly."""
    lb = lb or DEFAULT_LB
    branches = run["branches"]
    if not (0 <= branch_index < len(branches)):
        raise IndexError("concolic: bad branch index")
    atoms = []
    for ln, expr, truth in branches[:branch_index]:
        if truth is None:
            return {"status": "opaque-prefix"}
        try:
            cond = lower_condition(expr)
            atoms += atoms_of(cond if truth else _neg(cond))
        except Exception:
            return {"status": "opaque-prefix"}
    ln, expr, truth = branches[branch_index]
    if truth is None:
        return {"status": "opaque-branch"}
    try:
        cond = lower_condition(expr)
        atoms += atoms_of(_neg(cond) if truth else cond)
    except Exception:
        return {"status": "opaque-branch"}
    model = lb.learn(atoms)
    if not model.feasible():
        return {"status": "infeasible-flip", "constraints": atoms}
    values = model.model()
    if not values:
        return {"status": "no-model", "constraints": atoms}
    return {"status": "ok", "inputs": values, "constraints": atoms}


def flip_and_verify(fn, run, branch_index, source=None, lb=None) -> dict:
    """Full flip: solve, re-run, confirm the branch flipped.

    If the re-run disagrees with the symbolic expectation -> divergence
    reported (concrete/symbolic desync is a first-class citizen).

    Parameters the solver leaves unconstrained (they never appear in any
    branch condition) are not dropped from the re-run call -- that would
    silently shift every later positional argument into the wrong slot.
    They keep their concrete value from the original run instead."""
    out = flip(fn, run, branch_index, lb)
    if out["status"] != "ok":
        return out
    try:
        sig = inspect.signature(fn)
        bound = sig.bind(*run.get("args", ()), **run.get("kwargs", {}))
        bound.apply_defaults()
        base = dict(bound.arguments) # original concrete values
    except TypeError:
        base = {}
    base.update(out["inputs"]) # solved values win where present
    try:
        order = list(inspect.signature(fn).parameters)
        args = [base[k] for k in order if k in base]
    except (TypeError, ValueError):
        args = [base[k] for k in sorted(base)]
    try:
        new_run = trace_fn(fn, *args, source=source)
    except Exception as e:
        out["status"] = "rerun-error" # refuse loudly, never crash
        out["detail"] = {"error": repr(e), "args": args}
        return out
    i = branch_index
    if i < len(new_run["branches"]):
        ln, expr, truth = new_run["branches"][i]
        old_truth = run["branches"][i][2]
        if truth == old_truth:
            out["status"] = "divergence"
            out["detail"] = {"expected-flip-at": ln, "observed": truth}
            return out
    out["rerun"] = {"result": new_run["result"], "branches": new_run["branches"]}
    return out
