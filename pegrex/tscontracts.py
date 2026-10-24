"""
tscontracts - path contracts from tree-sitter CSTs.

Every supported tree-sitter language lowers to the same contract
shape as Python/COBOL/Fortran: [(frozenset(guard-atom-texts),
result-expression-text)]. If/else split paths; return ends a path;
loop subtrees are skipped (no unrolling -- honest scope); guards and
results come from source slices so anonymous tokens are not lost.
"""
from __future__ import annotations

import re

from .ir import lower_condition
from .linsolve import atoms_of, parse_atom
from .refine import _neg

_LANGS = {"go", "rust", "javascript", "typescript", "tsx", "julia",
           "kotlin", "zig", "solidity"}

_IF = {"if_statement", "if_expression"}
_BLOCK = {"block", "compound_statement", "statement_block",
           "brace_block", "then", "do_block", "block_statement",
           "function_body", "control_structure_body", "statement",
           "else_clause", "else"}
_RETURN = {"return_statement", "return_expression"}


def contracts(src: str, lang: str):
    if lang not in _LANGS:
        raise ValueError(f"tscontracts: unsupported language {lang!r}")
    from . import tree_sitter_bridge as tb
    tree = tb.parse(lang, src)
    raw = src.encode()
    out: list = []

    def slice_txt(a, b):
        return raw[a:b].decode(errors="replace")

    def cond_text(node):
        kids = [c for c in node.children if not isinstance(c, str)]
        end = None
        for c in kids:
            if c.tag in _BLOCK:
                end = c.pos
                break
        if end is None and kids:
            end = kids[-1].endpos
        if end is None:
            return None
        txt = slice_txt(node.pos, end).strip()
        txt = re.sub(r"^(if|while|for)\b", "", txt).strip()
        txt = txt.lstrip("(").rstrip(")").strip()
        if txt.startswith("{") or not txt:
            return None
        return txt

    def guard_atoms(txt):
        try:
            return atoms_of(lower_condition(txt))
        except Exception:
            return None

    def walk(node, guards, env):
        tag = node.tag
        if tag in _IF:
            cond = cond_text(node)
            atoms = guard_atoms(cond) if cond else None
            body, orelse = [], []
            for c in node.children:
                if isinstance(c, str):
                    continue
                if c.tag in _BLOCK:
                    (body if not body else orelse).append(c)
            blocks = [c for c in node.children
                      if not isinstance(c, str) and c.tag in _BLOCK]
            if len(blocks) == 1:
                if atoms:
                    walk(blocks[0], guards + atoms, env)
                else:
                    walk(blocks[0], guards, env)
            elif len(blocks) >= 2:
                if atoms:
                    walk(blocks[0], guards + atoms, env)
                    try:
                        neg = atoms_of(_neg(lower_condition(cond)))
                        walk(blocks[1], guards + neg, env)
                    except Exception:
                        walk(blocks[1], guards, env)
                else:
                    walk(blocks[0], guards, env)
                    walk(blocks[1], guards, env)
            return
        if tag in _RETURN:
            expr = re.sub(r"^\s*return\b", "", slice_txt(node.pos, node.endpos))
            expr = expr.split(";")[0].strip()
            if env.get("__result__") is None:
                env = dict(env)
                env["__result__"] = expr
            if "__result__" in env:
                out.append((frozenset(guards), env["__result__"]))
            return
        if tag in {"for_statement", "for_expression", "while_statement",
                   "while_expression", "do_statement", "loop_expression",
                   "match_statement", "match_expression"}:
            return
        for c in node.children:
            if not isinstance(c, str):
                walk(c, guards, env)

    def funcs(node):
        for c in node.children:
            if isinstance(c, str):
                continue
            if c.tag in {"function_item", "function_declaration",
                         "function_definition", "method_declaration",
                         "func_literal"}:
                yield c
            else:
                yield from funcs(c)

    for fn in funcs(tree):
        before = len(out)
        walk(fn, [], {})
        if len(out) == before:
            expr = slice_txt(fn.pos, fn.endpos)
            m = re.search(r"return\s+(.+?);?\s*\}\s*$", expr, re.S)
            if m:
                out.append((frozenset(), m.group(1).strip()))
    return out


def contracts_for_path(path: str):
    from .annotations import language_of
    lang = language_of(path)
    if lang not in _LANGS:
        raise ValueError(f"tscontracts: no CST contracts for {lang!r}")
    return contracts(open(path).read(), lang)