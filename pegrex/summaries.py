"""
summaries 

║  Function contracts: each path = (constraints -> result).  Compose them 
║  modularly, transitively, SMT-pruned, precedence-safe."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .cfg import CFG
from .paths import PathEnumerator
from .sym import Not, Sym
from .peg import Node

_LUA_BIN = {"eq": "==", "lt": "<", "le": "<=", "gt": ">", "ge": ">=",
            "ne": "~=", "add": "+", "sub": "-", "mul": "*", "div": "/",
            "idiv": "//", "mod": "%", "pow": "^", "concat": "..",
            "unm": "-", "not": "not ", "len": "#", "bnot": "~"}
_CALL = re.compile(r"([A-Za-z_]\w*)\(([^()]*)\)")
_OPS = (" + ", " - ", " * ", " / ")


def render_lua(x) -> str:
    if isinstance(x, list):
        return " ".join(render_lua(i) for i in x)
    if not isinstance(x, Node):
        return str(x)
    if x.tag == "Id":
        return str(x.children[0])
    if x.tag == "Number":
        return str(x.children[0])
    if x.tag == "Return":
        kids = [c for c in x.children]
        return render_lua(kids[0]) if kids else ""
    if x.tag == "Assign":
        p = x.children
        return f"{render_lua(p[0])} = {render_lua(p[1])}"
    if x.tag in ("BinaryOp", "UnaryOp"):
        p = x.children
        if len(p) >= 3:
            return f"{render_lua(p[0])} {_LUA_BIN.get(p[1], p[1])} {render_lua(p[2])}"
        if len(p) >= 2:
            return f"{_LUA_BIN.get(p[0], p[0])}{render_lua(p[1])}"
    if x.tag == "Call":
        kids = list(x.children)
        fn = kids[-1] if kids else "?"
        args = kids[0] if len(kids) > 1 else []
        return f"{render_lua(fn)}({render_lua(args)})"
    inner = " ".join(render_lua(c) for c in x.children if isinstance(c, (Node, list)))
    return inner or x.tag


def render_c(ch, src) -> str:
    """C expressions from raw children."""
    if isinstance(ch, Node):
        if ch.tag == "identifier":
            return str(ch.children[0])
        if ch.tag in ("unary_expression", "prefix_expression", "unary-operator"):
            return src[ch.pos:ch.endpos].strip()   # anonymous operator: slice
        if ch.tag in ("binary-operator", "assignment-operator"):
            return src[ch.pos:ch.endpos].strip()
        if ch.tag == "postfix-expression-suffix":  # folded call: [args, callee]
            kids = [k for k in ch.children if isinstance(k, Node)]
            if kids and kids[-1].tag == "identifier":
                args = " ".join(render_c(k, src) for k in kids[:-1])
                return f"{render_c(kids[-1], src)}({args})"
        if ch.tag in ("conditional-expression", "binary-expression",
                      "assignment-expression", "jump-statement"):
            return render_c(list(ch.children), src)
        return " ".join(render_c(k, src) for k in ch.children
                        if isinstance(k, (Node, str)))
    if isinstance(ch, list):
        if len(ch) == 1:
            return render_c(ch[0], src)
        if len(ch) >= 2 and isinstance(ch[-1], Node) and ch[-1].tag == "identifier":
            op_idx = [i for i, x in enumerate(ch[:-1])
                      if isinstance(x, Node) and x.tag == "binary-operator"]
            cut = op_idx[-1] if op_idx else -1
            args = ch[cut + 1:-1]
            call = f"{render_c(ch[-1], src)}({render_c(list(args), src)})"
            if cut < 0:
                return call
            ch = list(ch[:cut + 1]) + [call]
        out = []
        for x in ch:
            if isinstance(x, bool):
                continue
            if isinstance(x, Node) and x.tag == "binary-operator":
                out.append(src[x.pos:x.endpos].strip())
            elif isinstance(x, Node):
                out.append(render_c(x, src))
            else:
                out.append(str(x))
        return " ".join(t for t in out if t)
    return str(ch)


def _summaries_for_paths(cfg: CFG, cond, render, paths) -> list:
    out = []
    for path in paths:
        cons, result = [], None
        for i in range(len(path) - 1):
            for dst, e in cfg.successors(path[i]):
                if dst != path[i + 1] or e.cond is None:
                    continue
                if e.kind in ("then", "body"):
                    cons.append(str(cond(e.cond)))
                elif e.kind in ("else", "exit"):
                    base = e.cond[0] if isinstance(e.cond, tuple) else e.cond
                    cons.append(str(Not(cond(base))))
        for b in path:
            blk = cfg.blocks[b]
            if blk.term == "ret" and blk.stmts:
                result = render(blk.stmts[0])
        out.append((frozenset(cons), result))
    return sorted(out, key=lambda t: (sorted(t[0]), str(t[1])))


def path_summaries(cfg: CFG, cond, render, unroll: int = 1) -> list:
    """[(frozenset(constraints), result)] — the function's contract."""
    paths = PathEnumerator(cfg, unroll=unroll).enumerate()
    return _summaries_for_paths(cfg, cond, render, paths)


def path_summaries_bounded(cfg: CFG, cond, render, unroll: int = 1, *,
                           max_paths: int = 10_000,
                           timeout_ms: int | None = None) -> dict:
    """Contract extraction with explicit incomplete-enumeration semantics."""
    enumeration = PathEnumerator(cfg, unroll=unroll).enumerate_bounded(
        max_paths=max_paths, timeout_ms=timeout_ms)
    return {"contracts": (_summaries_for_paths(cfg, cond, render, enumeration.paths)
                          if enumeration.complete else []),
            "complete": enumeration.complete, "unknowns": enumeration.unknowns,
            "visited": enumeration.visited}


def _prune(paths):
    from .smt import learn
    kept = [(c, r) for c, r in paths if learn(c).feasible()]
    return sorted(kept, key=lambda t: (sorted(t[0]), str(t[1])))


def compose(caller, callee_name, callee_contract, param, arg) -> list:
    """Expand call sites through the callee's contract. Precedence-safe
    wrapping; SMT-pruned infeasible combinations."""
    call = f"{callee_name}({arg})"
    out = []
    for cons, res in caller:
        if not res or call not in res:
            out.append((cons, res))
            continue
        for ccons, cres in callee_contract:
            ren = lambda t: re.sub(rf"\b{param}\b", arg, t) if t else t
            newcons = frozenset(set(cons) | {ren(c) for c in ccons})
            rc = ren(cres)
            if rc and any(op in rc for op in _OPS):
                rc = f"({rc})"
            out.append((newcons, res.replace(call, rc if rc is not None else "?")))
    return _prune(out)


def expand_calls(entry_contract, contracts, params, max_fixpoint: int = 16) -> list:
    """Transitively expand every call to a fixed point. Callee contracts must
    already be expanded (bottom-up order)."""
    out = list(entry_contract)
    for _ in range(max_fixpoint):
        step, changed = [], False
        for cons, res in out:
            if not res or not (m := _CALL.search(res)) or m.group(1) not in contracts:
                step.append((cons, res))
                continue
            callee, arg = m.group(1), m.group(2).strip()
            step.extend(compose([(cons, res)], callee, contracts[callee],
                                params[callee], arg))
            changed = True
        out = _prune(step) if changed else out
        if not changed:
            break
    return out
