"""
cobolfront - native COBOL frontend

Parses a practical free-form COBOL subset into the SAME contract tuples
as the rest of the engine: [(frozenset(guard-atoms), result-expr)].

Subset:  *> comments with '*> pegrex: result ITEM' annotations,
        MOVE a TO b, COMPUTE b = expr, ADD/SUBTRACT a TO/FROM b,
        IF cond THEN ... [ELSE ...] END-IF, STOP RUN / GOBACK,
        CALL '<name>' [USING id ...] (recorded, externally 'unknown'),
        PERFORM p / PERFORM p THRU q / inline PERFORM (whole-program
        contracts via program_contracts only).
PERFORM loops with TIMES/UNTIL/VARYING and missing END-IF refuse loudly
-- never guessed. COPY copybooks expand via expand_copybooks(copydir).
Identifiers are case-insensitive (normalized to upper).
"""
from __future__ import annotations

import os
import re

from .ir import cond_to_atom, lower_condition, parse_expr, to_sym
from .legacy_common import atoms_of_cond, negate_atoms
from .sym import Op, V


class CobolError(ValueError):
    """Outside the certified COBOL fragment -- loud refusal."""


_RESULT_RX = re.compile(r"^\*>\s*pegrex:\s*result\s+(\w+)", re.I)
_ENTRY_RX = re.compile(r"^\*>\s*pegrex:\s*entry\s+(\w+)", re.I)
_IF_RX = re.compile(r"^IF\s+(.+?)\s+THEN$", re.I)
_ELSE_RX = re.compile(r"^ELSE$", re.I)
_ENDIF_RX = re.compile(r"^END-IF\.?$", re.I)
_MOVE_RX = re.compile(r"^MOVE\s+(.+?)\s+TO\s+(\w+)$", re.I)
_COMPUTE_RX = re.compile(r"^COMPUTE\s+(\w+)\s*=\s*(.+)$", re.I)
_ADD_RX = re.compile(r"^ADD\s+(.+?)\s+TO\s+(\w+)$", re.I)
_SUB_RX = re.compile(r"^SUBTRACT\s+(.+?)\s+FROM\s+(\w+)$", re.I)
_ENDPERF_RX = re.compile(r"^END-PERFORM\.?$", re.I)
_PERFORM_RX = re.compile(r"^PERFORM\s+([A-Za-z0-9][\w-]*)\s*\.?$", re.I)
_PERFORM_THRU_RX = re.compile(
    r"^PERFORM\s+([A-Za-z0-9][\w-]*)\s+THRU\s+([A-Za-z0-9][\w-]*)\s*\.?$",
    re.I)
_PERFORM_INLINE_RX = re.compile(r"^PERFORM\s*\.?$", re.I)
_CALL_RX = re.compile(
    r"^CALL\s+(['\"])([A-Za-z0-9][\w-]*)\1(?:\s+USING\s+(.+?))?\.?\s*$",
    re.I)
_CALL_SCAN = re.compile(
    r"^\s*CALL\s+(['\"])([A-Za-z0-9][\w-]*)\1(?:\s+USING\s+(.+?))?\.?\s*$",
    re.I)
_COPY_RX = re.compile(
    r"^COPY\s+([A-Za-z0-9][\w-]*)(\s+REPLACING\b.*)?\.?\s*$", re.I)
_COPY_EXT = (".cpy", ".CPY", ".cob", ".txt")
_LABEL_RX = re.compile(r"^\s*([A-Za-z][A-Za-z0-9-]{0,30})\s*\.\s*$")
_LABEL_EXCLUDE = {"END-IF", "ELSE", "GOBACK", "STOP", "EXIT", "CONTINUE",
                  "NEXT", "END", "PERFORM"}


def _cond_translate(text):
    t = text.strip()
    t = re.sub(r"(?<=\w)\s*=\s*(?=[\w(\-])", " == ", t)   # A = B -> A == B
    t = re.sub(r"\bAND\b", "and", t, flags=re.I)
    t = re.sub(r"\bOR\b", "or", t, flags=re.I)
    return t


def _expr(text, env):
    e = to_sym(parse_expr(text.strip()))
    return _resolve(e, env)


def _resolve(e, env):
    """Alias data items through the assignment environment."""
    from .sym import Sym
    if isinstance(e, Sym) and e.name.upper() in env:
        return env[e.name.upper()]
    if isinstance(e, Op):
        return Op(e.op, tuple(_resolve(a, env) for a in e.args))
    return e


def _statements(lines):
    """Group raw lines into a nested statement list."""
    out = []
    i = 0
    while i < len(lines):
        raw = lines[i].strip()
        if _ELSE_RX.match(raw) or _ENDIF_RX.match(raw) \
                or _ENDPERF_RX.match(raw):
            return out, i               # unwind to the matching IF/PERFORM
        if not raw or raw.startswith("*>") or re.match(
                r"^(IDENTIFICATION|DATA|PROCEDURE|ENVIRONMENT|WORKING-STORAGE|"
                r"LINKAGE|FILE|LOCAL-STORAGE|PROGRAM-ID)[\s\.]",
                raw, re.I) or (re.match(r"^\d*\s+[A-Z0-9-]+\s*\.$", raw)
                               and not raw.lstrip().upper().startswith("END-")) \
                or re.match(r"^[A-Z0-9-]+\s+SECTION\.?$", raw):
            i += 1                      # divisions, section headers, comments
            continue
        m = _IF_RX.match(raw)
        if m:
            base = i + 1                       # absolute index of IF body start
            body, r1 = _statements(lines[base:])
            else_at = base + r1                # absolute index of ELSE/END-IF
            orelse = []
            if else_at < len(lines) and _ELSE_RX.match(lines[else_at].strip()):
                orelse, r2 = _statements(lines[else_at + 1:])
                end_at = else_at + 1 + r2
            else:
                end_at = else_at
            if end_at >= len(lines) or not _ENDIF_RX.match(lines[end_at].strip()):
                raise CobolError(f"cobol: missing END-IF for {raw!r}")
            out.append(("if", _cond_translate(m.group(1)), body, orelse))
            i = end_at + 1
            continue
        if re.match(r"^(STOP RUN|GOBACK)\b", raw, re.I):
            out.append(("stop",))
            i += 1
            continue
        if re.match(r"^PERFORM\b", raw, re.I):
            m = _PERFORM_THRU_RX.match(raw)
            if m:
                out.append(("perform_thru", m.group(1).upper(),
                            m.group(2).upper()))
                i += 1
                continue
            m = _PERFORM_RX.match(raw)
            if m:
                out.append(("perform", m.group(1).upper()))
                i += 1
                continue
            if _PERFORM_INLINE_RX.match(raw):
                body, r = _statements(lines[i + 1:])
                end_at = i + 1 + r
                if end_at >= len(lines) or not _ENDPERF_RX.match(
                        lines[end_at].strip()):
                    raise CobolError(f"cobol: missing END-PERFORM for "
                                     f"{raw!r}")
                out.append(("perform_inline", body))
                i = end_at + 1
                continue
            raise CobolError(f"cobol: PERFORM loops (TIMES/UNTIL/VARYING) "
                             f"are outside the certified fragment -- "
                             f"refused: {raw!r}")
        m = _CALL_RX.match(raw)
        if m:
            using = [u.upper() for u in re.split(r"[\s,]+", m.group(3) or "")
                     if u]
            out.append(("call", m.group(2).upper(), using))
            i += 1
            continue
        m = _MOVE_RX.match(raw)
        if m:
            out.append(("move", m.group(1).strip(), m.group(2).upper()))
            i += 1
            continue
        m = _COMPUTE_RX.match(raw)
        if m:
            out.append(("compute", m.group(1).upper(), m.group(2).strip()))
            i += 1
            continue
        m = _ADD_RX.match(raw)
        if m:
            out.append(("add", m.group(1).strip(), m.group(2).upper()))
            i += 1
            continue
        m = _SUB_RX.match(raw)
        if m:
            out.append(("sub", m.group(1).strip(), m.group(2).upper()))
            i += 1
            continue
        if re.match(r"^END\b", raw, re.I):
            i += 1
            continue
        raise CobolError(f"cobol: unsupported statement {raw!r}")
    return out, i


def _result_item(lines):
    for l in lines:
        m = _RESULT_RX.match(l.strip())
        if m:
            return m.group(1).upper()
    return None


def _contracts_from_stmts(stmts, result_item):
    """[(frozenset(guard-atoms), result-expr)] for every straight-line path."""
    out = []

    def walk(ss, env, guards):
        for st in ss:
            if st[0] == "stop":
                if result_item not in env:
                    raise CobolError(
                        f"cobol: result item {result_item} never assigned")
                out.append((frozenset(guards), str(env[result_item])))
                return
            if st[0] == "if":
                atoms = atoms_of_cond(st[1])
                walk(st[2], dict(env), guards + atoms)
                walk(st[3], dict(env), guards + negate_atoms(st[1]))
                return
            env = apply_stmt(st, env)
        if result_item not in env:
            raise CobolError(f"cobol: result item {result_item} never assigned")
        out.append((frozenset(guards), str(env[result_item])))

    walk(stmts, {}, [])
    def up(s):
        return re.sub(r"[A-Za-z_]\w*", lambda m: m.group(0).upper(), s)
    return [(frozenset(up(a) for a in cs), up(res)) for cs, res in out]


def contracts(src, result_item=None):
    """[(frozenset(guard-atoms), result-expr)] for every straight-line path
    of a SINGLE paragraph (the m113 certified behavior, unchanged)."""
    lines = src.splitlines()
    if result_item is None:
        result_item = _result_item(lines)
    if not result_item:
        raise CobolError("cobol: no result item -- add '*> pegrex: RESULT NAME'")
    stmts, _ = _statements(lines)
    return _contracts_from_stmts(stmts, result_item)


# COPY copybooks

def expand_copybooks(src, copydir, _seen=()):
    """Expand `COPY <book>.` lines with the book file's content.

    Looks for copydir/<book> with extensions .cpy, .CPY, .cob, .txt in
    that order. Nested COPY lines inside a book are expanded recursively
    with a cycle guard (a COPY cycle refuses loudly naming the chain).
    COPY ... REPLACING refuses loudly (naming the book) -- substitution
    semantics are not modeled. Idempotent: source without COPY lines is
    returned unchanged. Missing book -> CobolError naming book and dir.
    """
    seen_upper = {b.upper() for b in _seen}
    out = []
    changed = False
    for line in src.splitlines():
        s = line.strip()
        m = _COPY_RX.match(s) if s and not s.startswith("*>") else None
        if not m:
            out.append(line)
            continue
        book = m.group(1)
        if m.group(2):
            raise CobolError(f"cobol: COPY {book} REPLACING is not "
                             f"supported -- refusing (book {book!r})")
        if book.upper() in seen_upper:
            chain = " -> ".join(list(_seen) + [book])
            raise CobolError(f"cobol: COPY cycle detected: {chain}")
        path = None
        for ext in _COPY_EXT:
            cand = os.path.join(copydir, book + ext)
            if os.path.isfile(cand):
                path = cand
                break
        if path is None:
            raise CobolError(f"cobol: COPYBOOK {book!r} not found in "
                             f"{copydir!r} (tried .cpy .CPY .cob .txt)")
        with open(path) as f:
            content = f.read()
        out.append(expand_copybooks(content, copydir, _seen + (book,)))
        changed = True
    if not changed:
        return src
    return "\n".join(out)


# CALL linkage

def linkage(src):
    """CALL statements as [{'name', 'using': [vars]}] in source order."""
    out = []
    for line in src.splitlines():
        m = _CALL_SCAN.match(line)
        if m:
            using = [u.upper() for u in re.split(r"[\s,]+", m.group(3) or "")
                     if u]
            out.append({"name": m.group(2).upper(), "using": using})
    return out


def link_contracts(src):
    """called-program -> {'using': [vars], 'verdict': 'unknown (external)'}."""
    out = {}
    for c in linkage(src):
        e = out.setdefault(c["name"], {"using": [],
                                       "verdict": "unknown (external)"})
        for v in c["using"]:
            if v not in e["using"]:
                e["using"].append(v)
    return out


# Whole-program contracts with cross-paragraph PERFORM dataflow

def _split_paragraphs(lines):
    """Paragraph name -> body lines, in declaration order. A paragraph
    header is a lone 'LABEL.' line (division/section/END-IF/GOBACK-style tokens excluded)."""
    paras = {}
    order = []
    current = None
    for raw in lines:
        s = raw.strip()
        m = _LABEL_RX.match(raw) if s and not s.startswith("*>") else None
        if m and m.group(1).upper() not in _LABEL_EXCLUDE:
            name = m.group(1).upper()
            if name not in paras:
                paras[name] = []
                order.append(name)
            current = name
            continue
        if current is not None:
            paras[current].append(raw)
    return paras, order


def _flatten_performs(parsed, order, entry):
    """Inline the PERFORM chain reachable from entry in DFS order, so a
    MOVE in an earlier performed paragraph is visible to later ones.
    Cycles and unknown targets refuse loudly (named)."""
    out = []

    def emit(ss, stack):
        for st in ss:
            if st[0] == "perform":
                visit(st[1], stack)
            elif st[0] == "perform_thru":
                a, b = st[1], st[2]
                if a not in parsed or b not in parsed:
                    raise CobolError(f"cobol: PERFORM {a} THRU {b} names an "
                                     f"unknown paragraph")
                i, j = order.index(a), order.index(b)
                if i > j:
                    raise CobolError(f"cobol: PERFORM {a} THRU {b}: {a} "
                                     f"declared after {b}")
                for p in order[i:j + 1]:
                    visit(p, stack)
            elif st[0] == "perform_inline":
                emit(st[1], stack)
            else:
                out.append(st)

    def visit(name, stack):
        if name in stack:
            raise CobolError(f"cobol: PERFORM cycle detected: "
                             f"{' -> '.join(stack + [name])}")
        if name not in parsed:
            raise CobolError(f"cobol: PERFORM target {name!r} has no "
                             f"paragraph")
        emit(parsed[name], stack + [name])

    visit(entry, [])
    return out


def program_contracts(src, entry=None) -> dict:
    """Whole-program contracts with cross-paragraph dataflow.

    Paragraphs are discovered; PERFORM chains (PERFORM p, PERFORM p THRU
    q, inline PERFORM) are inlined in DFS order from `entry` (explicit
    arg, or '*> pegrex: entry NAME', or the first paragraph). PERFORM
    TIMES/UNTIL/VARYING loops refuse loudly with the reason; PERFORM
    cycles refuse loudly naming the chain. A MOVE in an earlier
    performed paragraph is visible in the contracts of later ones.

    Returns {"entry", "paragraphs", "calls", "result_item", "contracts"}
    where "contracts" has the exact same tuple shape as contracts().
    CALLs are reported as 'unknown (external)' -- external semantics are never invented."""
    lines = src.splitlines()
    result_item = _result_item(lines)
    if not result_item:
        raise CobolError("cobol: no result item -- add '*> pegrex: RESULT NAME'")
    if entry is None:
        for l in lines:
            m = _ENTRY_RX.match(l.strip())
            if m:
                entry = m.group(1).upper()
                break
    paras, order = _split_paragraphs(lines)
    if not paras:
        stmts, _ = _statements(lines)
        flat = stmts
        entry = entry or "MAIN"
        order = [entry]
    else:
        if entry is None:
            entry = order[0]
        if entry not in paras:
            raise CobolError(f"cobol: entry paragraph {entry!r} not found")
        parsed = {}
        for name in order:
            stmts, _ = _statements(paras[name])
            parsed[name] = stmts
        flat = _flatten_performs(parsed, order, entry)
    return {"entry": entry, "paragraphs": order,
            "calls": link_contracts(src), "result_item": result_item,
            "contracts": _contracts_from_stmts(flat, result_item)}


def apply_stmt(st, env):
    op = st[0]
    if op == "move":
        src_s, dst = st[1], st[2]
        if re.fullmatch(r"[+-]?\d+", src_s):
            env[dst] = int(src_s)
        else:
            env[dst] = _resolve(V(src_s.upper()), env)
    elif op == "compute":
        env[st[1]] = _expr(st[2], env)
    elif op == "add":
        aug = _expr(st[1], env)
        env[st[2]] = Op("+", (env.get(st[2], V(st[2])), aug))
    elif op == "sub":
        aug = _expr(st[1], env)
        env[st[2]] = Op("-", (env.get(st[2], V(st[2])), aug))
    elif op == "call":
        return env     # external: no known local effect -- recorded via
                       # linkage()/link_contracts(), verdict 'unknown
                       # (external)'; never invented
    elif op in ("perform", "perform_thru", "perform_inline"):
        raise CobolError(f"cobol: PERFORM chains are outside the "
                         f"single-paragraph contracts() -- use "
                         f"program_contracts() for cross-paragraph "
                         f"dataflow: {st!r}")
    else:
        raise CobolError(f"cobol: internal: {st}")
    return env
