"""
║  difforacle

║  Differential-compiler oracle: pegrex path contracts vs the semantics of
║  a cc-compiled (-O0) binary.  A seeded generator emits tiny, UB-free C 
║  functions; for every sampled input the engine asks two oracles — the 
║  contract (symbolic, via the c11 frontend) and the binary (concrete) — 
║  and reports any disagreement as a finding.  A UB canary (deliberate
║  signed overflow) proves the harness is not vacuously green.

║  Three-valued throughout: a missing/broken compiler is verdict
║  "refused" naming the error — never a crash, never a silent pass.
"""
from __future__ import annotations

import ast
import os
import random
import re
import shutil
import subprocess
import tempfile

from .linsolve import parse_atom


class DifforacleError(ValueError):
    """Case outside the supported subset or unsafe construct — loud refusal."""


# Safe expression evaluator: ast-walked, whitelist {+,-,*,//, ints, vars},
# comparisons and boolean not.  No eval()/exec() anywhere.

_BIN = {ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b,
        ast.Mult: lambda a, b: a * b, ast.FloorDiv: lambda a, b: a // b}
_CMP = {ast.Eq: lambda a, b: a == b, ast.NotEq: lambda a, b: a != b,
        ast.Lt: lambda a, b: a < b, ast.LtE: lambda a, b: a <= b,
        ast.Gt: lambda a, b: a > b, ast.GtE: lambda a, b: a >= b}


def _unwrap(src: str) -> str:
    """Strip one layer of wrapping parens at a time, only when balanced."""
    t = src.strip()
    while t.startswith("(") and t.endswith(")"):
        depth, ok = 0, True
        for i, ch in enumerate(t):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0 and i != len(t) - 1:
                    ok = False
                    break
        if not ok:
            break
        t = t[1:-1].strip()
    return t


def _safe_eval_node(node, env: dict):
    if isinstance(node, ast.Expression):
        return _safe_eval_node(node.body, env)
    if isinstance(node, ast.Constant):
        if isinstance(node.value, int) and not isinstance(node.value, bool):
            return node.value
        raise DifforacleError(f"difforacle: non-int constant {node.value!r}")
    if isinstance(node, ast.Name):
        if node.id not in env:
            raise DifforacleError(f"difforacle: unbound variable {node.id!r}")
        return env[node.id]
    if isinstance(node, ast.BinOp) and type(node.op) in _BIN:
        return _BIN[type(node.op)](_safe_eval_node(node.left, env),
                                   _safe_eval_node(node.right, env))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub):
        return -_safe_eval_node(node.operand, env)
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.UAdd):
        return _safe_eval_node(node.operand, env)
    if isinstance(node, ast.Compare) and len(node.ops) == 1 \
            and type(node.ops[0]) in _CMP:
        return _CMP[type(node.ops[0])](_safe_eval_node(node.left, env),
                                       _safe_eval_node(node.comparators[0], env))
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        return not _safe_eval_node(node.operand, env)
    raise DifforacleError(
        f"difforacle: unsupported expression node {type(node).__name__}")


def safe_eval(expr: str, env: dict):
    """Evaluate a restricted arithmetic/boolean expression. Whitelist:
    + - * // (unary -), int constants, variables, == != < <= > >=, not.
    Raises DifforacleError on anything else — no eval/exec, ever."""
    t = re.sub(r"(?<![<>=!])=(?!=)", "==", _unwrap(expr))  # sym Eq renders '='
    try:
        tree = ast.parse(t, mode="eval")
    except SyntaxError as e:
        raise DifforacleError(f"difforacle: cannot parse expression {expr!r}: {e}")
    return _safe_eval_node(tree, env)


def atom_holds(text: str, env: dict) -> bool:
    """One path-constraint atom (e.g. '(n > 0)', '(not (n = 3))') on env."""
    return bool(safe_eval(text, env))


# ---------------------------------------------------------------------------
# Seeded case generator — UB-free BY CONSTRUCTION:
#   * params sampled in [-4, 4], constants 1..9, expressions at most two
#     factors wide  ->  |values| <= 9*(4*9) < 1500, far inside int32;
#     signed overflow is impossible for the generated programs.
#   * no division, no shifts, no casts -> no UB of any other kind either.
#   * every emitted expression shape is one whose c11-gram parse renders
#     faithfully (verified empirically by the oracle's agree runs).
# ---------------------------------------------------------------------------

def _pick_expr(rng, params):
    """A small random arithmetic expression over params/constants 1..9,
    restricted to shapes the c11 grammar parses and renders verbatim."""
    a = lambda: rng.choice(params)
    c = lambda: str(rng.randint(1, 9))
    p1, p2 = a(), a()
    shape = rng.randint(0, 9)
    if shape == 0:
        return p1
    if shape == 1:
        return f"-{p1}"
    if shape == 2:
        return c()
    if shape == 3:
        return f"{p1} + {c()}"
    if shape == 4:
        return f"{p1} - {c()}"
    if shape == 5:
        return f"{p1} * {c()}"
    if shape == 6:
        return f"{p1} + {p2}"
    if shape == 7:
        return f"{p1} - {p2}"
    if shape == 8:
        return f"{p1} * {p2}"
    return f"{p1} + {p2} + {c()}"      # constants last: c11 flat-chain rule


def _pick_guard(rng, params):
    op = rng.choice(["==", "<", "<=", ">", ">="])
    return f"{rng.choice(params)} {op} {rng.randint(1, 9)}"


def gen_case(rng) -> dict:
    """One tiny C function: 1-2 int params, 0-3 if/else on linear guards,
    arithmetic over {+, -, *, params, constants 1..9}, single `return`."""
    nparams = rng.choice([1, 2])
    params = ["a", "b"][:nparams]
    nifs = rng.randint(0, 3)
    sig = ", ".join(f"int {p}" for p in params)
    lines = [f"int f({sig}) {{"]
    if nifs == 0:
        lines.append(f"    return {_pick_expr(rng, params)};")
    else:
        lines.append(f"    int r = {_pick_expr(rng, params)};")
        for _ in range(nifs):
            g = _pick_guard(rng, params)
            lines.append(f"    if ({g}) {{")
            lines.append(f"        r = {_pick_expr(rng, params)};")
            lines.append("    } else {")
            lines.append(f"        r = {_pick_expr(rng, params)};")
            lines.append("    }")
        lines.append("    return r;")
    lines.append("}")
    return {"src": "\n".join(lines) + "\n", "name": "f"}


# ---------------------------------------------------------------------------
# Case parsing (the generator's exact subset) + pegrex contract extraction
# ---------------------------------------------------------------------------

_HEADER_RE = re.compile(r"int\s+f\s*\(([^)]*)\)")
_IF_RE = re.compile(
    r"if\s*\(([^)]+)\)\s*\{\s*r\s*=\s*([^;]+);?\s*\}\s*else\s*{\s*r\s*=\s*([^;]+);?\s*\}")
_INIT_RE = re.compile(r"int\s+r\s*=\s*([^;]+);")
_RETURN_RE = re.compile(r"return\s+([^;]+);")


def _params_of(src: str) -> list:
    m = _HEADER_RE.search(src)
    if not m:
        raise DifforacleError("difforacle: cannot parse function header")
    return [p.split()[-1] for p in m.group(1).split(",") if p.strip()]


def _parse_case(src: str) -> dict:
    """The generator's subset: optional init, 0-3 if/else assignments to r,
    single return.  Loud refusal outside the subset."""
    init = _INIT_RE.search(src)
    ifs = [(g.strip(), t.strip(), e.strip()) for g, t, e in _IF_RE.findall(src)]
    ret = _RETURN_RE.findall(src)
    if not ret:
        raise DifforacleError("difforacle: no `return` in case source")
    if init is None:
        if ifs:
            raise DifforacleError(
                "difforacle: if/else without `int r` init is outside the subset")
        return {"init": None, "ifs": [], "ret": ret[-1].strip()}
    return {"init": init.group(1).strip(), "ifs": ifs, "ret": ret[-1].strip()}


_contract_cache: dict = {}


def _contracts_for(src: str) -> list:
    """[(frozenset(constraints), result)] via the REAL c11 frontend path:
    pipeline.FRONTENDS['c'] -> CFG -> path_constraints/path_summaries."""
    if src in _contract_cache:
        return _contract_cache[src]
    import pipeline
    from .cfg import CFGBuilder
    from .summaries import path_summaries, render_c
    parse, tagspec, make_cond = pipeline.frontend_for("c")
    body = parse(src)                       # PREPROCESS
    cfg = CFGBuilder(tagspec).build(body)   # CFG
    cond = make_cond(src)
    contracts = path_summaries(cfg, cond, lambda st: render_c(st, src), 1)
    _contract_cache[src] = contracts
    return contracts


def contract_result(case: dict, args):
    """The pegrex-contract oracle: find the path whose linear constraints
    hold for `args`, evaluate its return expression with the safe evaluator.
    None = no analyzed path covers these inputs (three-valued, not an error);
    raises DifforacleError for sources outside the supported subset."""
    src, name = case["src"], case.get("name", "f")
    params = _params_of(src)
    if len(args) != len(params):
        raise DifforacleError(
            f"difforacle: {name} expects {len(params)} args, got {len(args)}")
    env = dict(zip(params, args))
    contracts = _contracts_for(src)
    chosen = None
    for cons, _res in contracts:
        if all(atom_holds(c, env) for c in cons):
            chosen = (cons, _res)
            break
    if chosen is None:
        return None
    cons, result = chosen
    struct = _parse_case(src)
    if struct["ifs"]:
        # copy propagation: the matched path's constraints ARE the guard
        # outcomes; evaluate the guards on the concrete inputs to pick the
        # assignment taken, then evaluate `return r`.
        val = safe_eval(struct["init"], env)
        loc = dict(env, r=val)
        for guard, then_e, else_e in struct["ifs"]:
            val = safe_eval(then_e if safe_eval(guard, loc)
                            else else_e, loc)
            loc["r"] = val
        return safe_eval(struct["ret"], loc)
    return safe_eval(struct["ret"], env)


# ---------------------------------------------------------------------------
# Binary oracle: compile with cc -O0, run, parse stdout int
# ---------------------------------------------------------------------------

def _wrap_main(case: dict) -> str:
    name = case.get("name", "f")
    params = _params_of(case["src"])
    argv = ", ".join(f"atoi(argv[{i + 1}])" for i in range(len(params)))
    return ("#include <stdio.h>\n#include <stdlib.h>\n"
            + case["src"]
            + f"\nint main(int argc, char **argv) {{\n"
            + f'    printf("%d\\n", {name}({argv}));\n'
            + "    return 0;\n}\n")


def _compile(cc, case, workdir, timeout):
    """-> path to binary; raises DifforacleError naming the compiler error."""
    cpath = os.path.join(workdir, f"{case.get('name', 'f')}.c")
    bpath = os.path.join(workdir, case.get("name", "f"))
    with open(cpath, "w", encoding="utf-8") as fh:
        fh.write(_wrap_main(case))
    try:
        proc = subprocess.run([cc, "-O0", "-o", bpath, cpath],
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise DifforacleError(f"compiler {cc}: compile timed out ({timeout}s)")
    except OSError as e:
        raise DifforacleError(f"compiler {cc}: {e}")
    if proc.returncode != 0:
        raise DifforacleError(
            f"compiler {cc} failed (rc={proc.returncode}): "
            f"{(proc.stderr or '').strip()[:300]}")
    return bpath


def _run_binary(bpath, args, timeout) -> int:
    try:
        proc = subprocess.run([bpath, *[str(a) for a in args]],
                              capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        raise DifforacleError(f"binary timed out after {timeout}s")
    if proc.returncode != 0:
        raise DifforacleError(
            f"binary exited rc={proc.returncode}: {(proc.stderr or '').strip()[:200]}")
    try:
        return int(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        raise DifforacleError(f"binary output not an int: {proc.stdout!r}")


def binary_result(cc, case, args, timeout=10) -> int:
    """Compile `case` with [cc, -O0] in a tempdir and run it on `args`.
    Raises DifforacleError (naming compiler/runner cause) — run() converts
    those into a refused verdict; direct callers get the loud error."""
    workdir = tempfile.mkdtemp(prefix="difforacle-")
    bpath = _compile(cc, case, workdir, timeout)
    return _run_binary(bpath, args, timeout)


# The oracle run

CANARY_SRC = "int f(int a) {\n    return (a * 40000) * 40000;\n}\n"


def run(seed=0, n=20, cc="cc", timeout=10) -> dict:
    """Sample n generated cases x <=16 small inputs; contract vs binary.
    Any disagreement -> finding kind 'divergence' (contract silence where
    the binary speaks is a finding too, kind 'contract-none').  Missing or
    broken compiler -> verdict 'refused' naming the error — never a crash."""
    if shutil.which(cc) is None:
        return {"cases": n, "checked": 0, "findings": [], "cc": cc,
                "verdict": "refused",
                "refusal": f"compiler {cc!r} not found on PATH"}
    rng = random.Random(seed)
    cases = [gen_case(rng) for _ in range(n)]
    findings, checked = [], 0
    for case in cases:
        params = _params_of(case["src"])
        grid = [t for t in __import__("itertools").product(range(-4, 5),
                                                           repeat=len(params))]
        argsets = rng.sample(grid, 16) if len(grid) > 16 else grid
        workdir = tempfile.mkdtemp(prefix="difforacle-")
        try:
            bpath = _compile(cc, case, workdir, timeout)
        except DifforacleError as e:
            return {"cases": n, "checked": checked, "findings": findings,
                    "cc": cc, "verdict": "refused", "refusal": str(e)}
        for args in argsets:
            checked += 1
            try:
                bval = _run_binary(bpath, args, timeout)
            except DifforacleError as e:
                findings.append({"case_src": case["src"], "args": list(args),
                                 "binary": None, "contract": None,
                                 "kind": f"binary-error: {e}"})
                continue
            try:
                cval = contract_result(case, list(args))
            except DifforacleError as e:
                findings.append({"case_src": case["src"], "args": list(args),
                                 "binary": bval, "contract": None, "kind": str(e)})
                continue
            if cval is None:
                findings.append({"case_src": case["src"], "args": list(args),
                                 "binary": bval, "contract": None,
                                 "kind": "contract-none"})
            elif bval != cval:
                findings.append({"case_src": case["src"], "args": list(args),
                                 "binary": bval, "contract": cval,
                                 "kind": "divergence"})
    return {"cases": n, "checked": checked, "findings": findings, "cc": cc,
            "verdict": "divergence" if findings else "agree"}


def run_canary(case=None, args_list=None, cc="cc", timeout=10) -> dict:
    """The UB canary: a case with deliberate signed overflow where contract
    math (exact integers) and the -O0 binary (wrapping int32) may disagree.
    Classified either way — the point is the harness reports what it sees."""
    case = case or {"src": CANARY_SRC, "name": "f"}
    if args_list is None:
        args_list = [[2], [3], [5], [-2]]
    out = {"canary_src": case["src"], "results": []}
    if shutil.which(cc) is None:
        out.update({"classified": "refused",
                    "refusal": f"compiler {cc!r} not found on PATH"})
        return out
    workdir = tempfile.mkdtemp(prefix="difforacle-canary-")
    try:
        bpath = _compile(cc, case, workdir, timeout)
    except DifforacleError as e:
        out.update({"classified": "refused", "refusal": str(e)})
        return out
    for args in args_list:
        entry = {"args": list(args)}
        try:
            entry["binary"] = _run_binary(bpath, args, timeout)
            entry["contract"] = contract_result(case, list(args))
            entry["agree"] = entry["binary"] == entry["contract"]
        except DifforacleError as e:
            entry["error"] = str(e)
        out["results"].append(entry)
    div = next((r for r in out["results"]
                if r.get("agree") is False), None)
    if div is not None:
        out.update({"classified": "divergence",
                    "finding": {"case_src": case["src"],
                                "args": div["args"],
                                "binary": div["binary"],
                                "contract": div["contract"],
                                "kind": "divergence"}})
    else:
        out.update({"classified": "agree", "finding": None})
    return out
