"""
cognitive - cognitive complexity for Python

Reimplemented from the complexipy engine (rohaquinlop/complexipy,
crates/complexipy-core/src/cognitive_complexity.rs) after spidering the
project: per-construct cost = 1 + nesting + boolean_ops; boolean and/or
counted per operator; elif chains +1 per clause; except handlers
+1 + nesting; direct recursion +1. Regions (Loop/If/ElifChain/Try/Match/
With) carry line spans and power the refactor plans: functions over
budget get extract-region suggestions with exact line ranges.

Three-valued: syntax errors are unknown with the reason --
never a crash, never a zero score."""

from __future__ import annotations

import ast


class CognitiveError(ValueError):
    pass


def _bool_ops(node):
    """Count boolean and/or operators in an expression subtree."""
    n = 0
    for sub in ast.walk(node):
        if isinstance(sub, ast.BoolOp):
            n += len(sub.values) - 1
    return n


def _line(node):
    return getattr(node, "lineno", 0)


def _recurses(body, name):
    for node in ast.walk(ast.Module(body=body, type_ignores=[])):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == name:
            return True
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                             ast.ClassDef)) and node is not body[0] if body else False:
            continue
    return False


def _direct_recursion(fn):
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id == fn.name:
            return _line(node)
    return None


class _Result:
    def __init__(self):
        self.complexity = 0
        self.lines = []  # (line, delta)
        self.regions = []


def _push(res, line, delta):
    res.complexity += delta
    if delta:
        res.lines.append((line, delta))


def _suite(body, nesting):
    out = _Result()
    for st in body:
        sub = _stmt(st, nesting)
        out.complexity += sub.complexity
        out.lines.extend(sub.lines)
        out.regions.extend(sub.regions)
    return out


def _loop(node, control, body, orelse, nesting):
    res = _Result()
    boolean = _bool_ops(control)
    own = 1 + nesting + boolean
    _push(res, _line(node), own)
    sub = _suite(body, nesting + 1)
    res.complexity += sub.complexity
    res.lines.extend(sub.lines)
    res.regions.extend(sub.regions)
    sub2 = _suite(orelse, nesting)
    res.complexity += sub2.complexity
    res.lines.extend(sub2.lines)
    res.regions.extend(sub2.regions)
    res.regions.append({"kind": type(node).__name__, "line_start": _line(node),
                        "line_end": getattr(node, "end_lineno", _line(node)),
                        "own": own, "nesting": nesting,
                        "children": len(body)})
    return res


def _stmt(st, nesting):
    res = _Result()
    if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
        for sub in st.body:
            r = _stmt(sub, nesting + (1 if isinstance(sub, ast.FunctionDef) else 0))
            res.complexity += r.complexity
            res.lines.extend(r.lines)
            res.regions.extend(r.regions)
    elif isinstance(st, ast.ClassDef):
        for sub in st.body:
            if isinstance(sub, ast.FunctionDef):
                r = _stmt(sub, nesting)
                res.complexity += r.complexity
                res.regions.extend(r.regions)
    elif isinstance(st, ast.For) or isinstance(st, ast.While):
        return _loop(st, st.iter if isinstance(st, ast.For) else st.test,
                     st.body, st.orelse, nesting)
    elif isinstance(st, ast.If):
        boolean = _bool_ops(st.test)
        own = 1 + nesting + boolean
        _push(res, _line(st), own)
        sub = _suite(st.body, nesting + 1)
        res.complexity += sub.complexity
        res.lines.extend(sub.lines)
        res.regions.extend(sub.regions)
        elifs = 0
        for clause in [c for c in [st.orelse] if c]:
            pass
        cur = st.orelse
        chain = []
        while len(cur) == 1 and isinstance(cur[0], ast.If):
            chain.append(cur[0])
            cur = cur[0].orelse
        for c in chain:
            elifs += 1
            cb = _bool_ops(c.test)
            _push(res, _line(c), 1 + cb)
            sub = _suite(c.body, nesting + 1)
            res.complexity += sub.complexity
            res.lines.extend(sub.lines)
        if cur:
            sub = _suite(cur, nesting)
            res.complexity += sub.complexity
            res.lines.extend(sub.lines)
        res.regions.append({"kind": "ElifChain" if elifs else "If",
                            "line_start": _line(st),
                            "line_end": getattr(st, "end_lineno", _line(st)),
                            "own": own, "nesting": nesting,
                            "elifs": elifs})
    elif isinstance(st, ast.Try):
        sub = _suite(st.body, nesting)
        res.complexity += sub.complexity
        res.lines.extend(sub.lines)
        own = 0
        for h in st.handlers:
            delta = 1 + nesting
            own += delta
            _push(res, _line(h), delta)
            sub = _suite(h.body, nesting + 1)
            res.complexity += sub.complexity
            res.lines.extend(sub.lines)
        for extra in (st.orelse, st.finalbody):
            sub = _suite(extra, nesting)
            res.complexity += sub.complexity
            res.lines.extend(sub.lines)
        res.regions.append({"kind": "Try", "line_start": _line(st),
                            "line_end": getattr(st, "end_lineno", _line(st)),
                            "own": own, "handlers": len(st.handlers)})
    elif isinstance(st, ast.With):
        wb = sum(_bool_ops(i.context_expr) for i in st.items)
        if wb:
            _push(res, _line(st), wb)
        sub = _suite(st.body, nesting)
        res.complexity += sub.complexity
        res.lines.extend(sub.lines)
    elif isinstance(st, ast.Match):
        _push(res, _line(st), 1 + nesting)
        for case in st.cases:
            sub = _suite(case.body, nesting + 1)
            res.complexity += sub.complexity
            res.lines.extend(sub.lines)
        res.regions.append({"kind": "Match", "line_start": _line(st),
                            "line_end": getattr(st, "end_lineno", _line(st)),
                            "own": 1 + nesting})
    else:
        for attr in ("value", "test", "msg"):
            e = getattr(st, attr, None)
            if isinstance(e, ast.expr):
                b = _bool_ops(e)
                if b:
                    _push(res, _line(st), b)
    return res


def _refactor_plan(fn_name, complexity, regions, budget):
    """complexipy-style plan: over-budget functions get extract-region
    suggestions with exact line ranges."""
    if complexity <= budget:
        return []
    plans = []
    for r in regions:
        if r.get("own", 0) >= 2:
            plans.append({"action": "extract-region",
                          "function": fn_name,
                          "kind": r["kind"],
                          "lines": [r["line_start"], r["line_end"]]})
    return plans


def _cognitive_python(src, budget=7, with_plans=True):
    """Per-function cognitive complexity + regions + refactor plans.

    Three-valued: a syntax error returns {'verdict': 'unknown'} with the
    reason -- never a crash and never a fabricated zero."""
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        return {"verdict": "unknown",
                "reason": f"syntax error at line {e.lineno}: "
                          f"{(e.msg or '')[:100]}"}
    functions = []
    total = 0
    for node in tree.body:
        fns = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            fns = [node]
        elif isinstance(node, ast.ClassDef):
            fns = [n for n in node.body
                   if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
        for fn in fns:
            r = _stmt(fn, 0)
            rec = _direct_recursion(fn)
            if rec:
                _push(r, rec, 1)
            name = fn.name
            if isinstance(node, ast.ClassDef):
                name = f"{node.name}::{fn.name}"
            plans = _refactor_plan(name, r.complexity, r.regions, budget) \
                if with_plans else []
            functions.append({"name": name, "complexity": r.complexity,
                              "line_start": fn.lineno,
                              "line_end": getattr(fn, "end_lineno", fn.lineno),
                              "regions": r.regions,
                              "per_line": [{"line": l, "delta": d}
                                           for l, d in r.lines],
                              "refactor_plans": plans})
            total += r.complexity
    return {"verdict": "ok", "functions": functions, "total": total}


# ---------------------------------------------------------------------------
# multi-language cognitive complexity (tree-sitter CST walker)
# ---------------------------------------------------------------------------

_TS_LANGS = {"go", "rust", "javascript", "typescript", "tsx", "julia",
             "kotlin", "zig", "solidity"}
_IF = {"if_statement", "if_expression"}
_LOOP = {"for_statement", "for_expression", "while_statement",
          "while_expression", "do_statement", "loop_expression"}
_CATCH = {"except_clause", "catch_clause"}
_MATCH = {"match_statement", "match_expression", "switch_statement",
           "switch_expression"}
_FUNC = {"function_item", "function_declaration", "function_definition",
          "method_declaration", "func_literal"}
_CALL = {"call_expression", "call"}
_COND_TERNARY = {"conditional_expression", "ternary_expression"}
_BOOL_TOKENS = {"go": ("&&", "||"), "rust": ("&&", "||"),
                "javascript": ("&&", "||"), "typescript": ("&&", "||"),
                "tsx": ("&&", "||"), "julia": ("&&", "||"),
                "kotlin": ("&&", "||"), "zig": (" and ", " or "),
                "solidity": ("&&", "||")}


def _line_of(pos, starts):
    """byte offset -> 1-based line number."""
    import bisect
    return bisect.bisect_right(starts, pos)


def _cognitive_ts(src, lang, budget, with_plans):
    """Generic cognitive complexity over a tree-sitter CST (pegrex Nodes).
    Bool operators are counted from source slices (anonymous tokens are
    not in the CST); nested control bodies are subtracted so each
    operator counts once, at its outermost control node."""
    from . import tree_sitter_bridge as tb
    try:
        tree = tb.parse(lang, src)
    except Exception as e:
        return {"verdict": "unknown",
                "reason": type(e).__name__ + ": " + str(e)[:100]}
    toks = _BOOL_TOKENS.get(lang, ("&&", "||"))
    raw = src.encode()
    starts = [0]
    off = 0
    for ln in src.splitlines(keepends=True):
        off += len(ln.encode())
        starts.append(off)

    import re as _re
    _BOOL_RX = {"rust": _re.compile(r"&&|&\s*&|\|\||\|\s*\|"),
                "zig": _re.compile(r"\band\b|\bor\b")}

    def toks_in(a, b):
        seg = raw[a:b].decode(errors="replace")
        rx = _BOOL_RX.get(lang)
        if rx is not None:
            return len(rx.findall(seg))
        return seg.count(toks[0]) + seg.count(toks[1])

    res = _Result()
    func_ranges = []

    def enclosing_name(pos):
        for nm, s0, e0 in func_ranges:
            if s0 <= pos < e0:
                return nm
        return None

    def leaf_text(node):
        if len(node.children) == 1 and isinstance(node.children[0], str):
            return node.children[0]
        for ch in node.children:
            if isinstance(ch, str):
                return ch
            if not ch.children:
                seg = raw[ch.pos:ch.endpos].decode(errors="replace")
                if seg.strip():
                    return seg.strip()
            t = leaf_text(ch)
            if t:
                return t
        return None

    def walk(node, nesting, parent_tag=None):
        tag = node.tag
        is_ctrl = tag in _IF | _LOOP | _CATCH | _MATCH
        if tag in _FUNC:
            nm = leaf_text(node)
            if nm:
                func_ranges.append((nm, node.pos, node.endpos))
            for ch in node.children:
                if not isinstance(ch, str):
                    walk(ch, nesting)
            return
        child_ctrl_spans = []

        def collect_ctrl(node2):
            for ch2 in node2.children:
                if isinstance(ch2, str):
                    continue
                if ch2.tag in _IF | _LOOP | _CATCH | _MATCH | _COND_TERNARY:
                    child_ctrl_spans.append((ch2.pos, ch2.endpos))
                collect_ctrl(ch2)

        collect_ctrl(node)
        for ch in node.children:
            if isinstance(ch, str):
                continue
            bump = is_ctrl and not (tag in _IF and ch.tag in _IF)
            walk(ch, nesting + 1 if bump else nesting, tag)
        if tag in _COND_TERNARY:
            ln = _line_of(node.pos, starts)
            _push(res, ln, 1 + nesting)
            res.regions.append({"kind": "Ternary", "line_start": ln,
                                "line_end": _line_of(node.endpos, starts),
                                "own": 1 + nesting, "nesting": nesting})
            return
        if not is_ctrl:
            if tag in _CALL and func_ranges:
                callee = leaf_text(node)
                if callee and callee == enclosing_name(node.pos):
                    _push(res, _line_of(node.pos, starts), 1)
            return
        total = toks_in(node.pos, node.endpos)
        nested = sum(toks_in(a, b) for a, b in child_ctrl_spans)
        boolean = max(0, total - nested)
        is_elif = tag in _IF and parent_tag in _IF
        own = (1 if is_elif else 1 + nesting) + boolean
        if tag in _LOOP:
            kind = "Loop"
        elif tag in _CATCH:
            kind = "Try"
        elif tag in _MATCH:
            kind = "Match"
        else:
            kind = "ElifChain" if any(c.tag in _IF for c in node.children
                                      if not isinstance(c, str)) else "If"
        ln = _line_of(node.pos, starts)
        _push(res, ln, own)
        res.regions.append({"kind": kind, "line_start": ln,
                            "line_end": _line_of(node.endpos, starts),
                            "own": own, "nesting": nesting})

    walk(tree, 0)
    functions = []
    for nm, s0, e0 in func_ranges:
        ls, le = _line_of(s0, starts), _line_of(e0, starts)
        f_lines = [(l, d) for l, d in res.lines if ls <= l <= le]
        f_regions = [r for r in res.regions if ls <= r["line_start"] <= le]
        complexity = sum(d for _, d in f_lines)
        plans = _refactor_plan(nm, complexity, f_regions, budget) \
            if with_plans else []
        functions.append({"name": nm, "complexity": complexity,
                          "line_start": ls + 1,
                          "line_end": le + 1,
                          "regions": f_regions,
                          "per_line": [{"line": l, "delta": d}
                                       for l, d in f_lines],
                          "refactor_plans": plans})
    return {"verdict": "ok", "functions": functions,
            "total": sum(fg["complexity"] for fg in functions)}


def cognitive_complexity(src, lang=None, budget=7, with_plans=True):
    if lang is None or lang == "python":
        return _cognitive_python(src, budget=budget, with_plans=with_plans)
    if lang in _TS_LANGS:
        return _cognitive_ts(src, lang, budget, with_plans)
    return {"verdict": "unknown",
            "reason": "cognitive analysis not certified for " + repr(lang)}
