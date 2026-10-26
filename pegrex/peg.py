"""
peg

║  Packrat PEG engine — a Python port of the LPeg/LPegLabel subset. 
║  Memoized recursive descent: declarative like LPeg, never exponential. 
║  Error labels (Throw) are fatal by design, exactly as in LPegLabel."""

from __future__ import annotations

import itertools
from typing import Any, Callable

__all__ = [
    "Throw", "Patt", "Eps", "Lit", "AnyP", "SetP", "SeqP", "AltP", "RepP",
    "NotP", "AndP", "CapP", "CsP", "CtP", "CpP", "ValP", "FuncP", "CmtP",
    "FoldP", "GroupP", "BackP", "EqBackP", "ThrowP", "NodeP", "V", "Node",
    "Ctx", "run",
]


class Throw(Exception):
    """Abort the match with an error label + position (LPegLabel T)."""
    def __init__(self, label: str, pos: int) -> None:
        super().__init__(label)
        self.label, self.pos = label, pos


_ids = itertools.count(1)


class Node:
    """AST node from a `<==` rule. 0-based half-open positions."""
    __slots__ = ("tag", "pos", "endpos", "children")

    def __init__(self, tag, pos, endpos, children) -> None:
        self.tag, self.pos, self.endpos, self.children = tag, pos, endpos, children

    def __repr__(self) -> str:
        return f"Node({self.tag!r}, {self.pos}, {self.endpos}, {self.children!r})"


class Patt:
    """Base: match(s, pos, ctx) -> (newpos, caps) | None."""
    def __init__(self) -> None:
        self._id = next(_ids)


class Ctx:
    """Per-parse state: rules, user defs, memo table, named groups, records."""
    def __init__(self, rules, defs=None) -> None:
        self.rules = rules
        self.defs = defs or {}
        self.memo: dict = {}
        self.names: dict[str, list] = {}
        self.recorders: list = []

    def checkpoint(self):
        """Implement checkpoint with the module's explicit API and failure semantics."""
        return {k: len(v) for k, v in self.names.items()}

    def rollback(self, mark) -> None:
        """Implement rollback with the module's explicit API and failure semantics."""
        for k, n in mark.items():
            del self.names[k][n:]
        for k in [k for k in self.names if k not in mark]:
            del self.names[k]

    def run(self, p: Patt, s: str, pos: int):
        """Implement run with the module's explicit API and failure semantics."""
        if getattr(p, "_nomemo", False):        # match-time fns see live state
            return p.match(s, pos, self)
        if not isinstance(p, V):
            return p.match(s, pos, self)        # (packrat-classic, bounded memory)
        key = (p._id, pos)
        if key in self.memo:
            return self.memo[key]
        # Warth-style seed growing for LEFT recursion: begin with failure,
        # iterate the rule -- each pass may grow the seed -- to a fixpoint.
        self.memo[key] = None
        seed = None
        while True:
            r = p.match(s, pos, self)
            if r is None or (seed is not None and r[0] <= seed[0]):
                break
            seed = r
            self.memo[key] = r
        return self.memo[key]


def _record(ctx: Ctx, start: int, end: int, text: str) -> None:
    """Cs substitution span (drops records nested inside the new span)."""
    if not ctx.recorders:
        return
    rec = ctx.recorders[-1]
    rec[:] = [(a, b, t) for (a, b, t) in rec if not (start <= a and b <= end)]
    rec.append((start, end, text))


class Eps(Patt):
    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        return pos, []


class Lit(Patt):
    def __init__(self, text: str) -> None:
        super().__init__()
        self.text = text

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        return (pos + len(self.text), []) if s.startswith(self.text, pos) else None


class AnyP(Patt):
    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        return (pos + 1, []) if pos < len(s) else None


class SetP(Patt):
    """Char set: items = chars or (lo, hi) ranges; `complement` inverts."""
    def __init__(self, items, complement: bool = False) -> None:
        super().__init__()
        self.items, self.complement = items, complement

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        if pos >= len(s):
            return None
        c = s[pos]
        inside = any((c == i if isinstance(i, str) else i[0] <= c <= i[1])
                     for i in self.items)
        return (pos + 1, []) if inside != self.complement else None


class SeqP(Patt):
    def __init__(self, *ps) -> None:
        super().__init__()
        self.ps = ps

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        caps, p = [], pos
        for q in self.ps:
            if (r := ctx.run(q, s, p)) is None:
                return None
            p, cs = r
            caps.extend(cs)
        return p, caps


class AltP(Patt):
    def __init__(self, *ps) -> None:
        super().__init__()
        self.ps = ps

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        for q in self.ps:
            mark = ctx.checkpoint()
            if (r := ctx.run(q, s, pos)) is not None:
                return r
            ctx.rollback(mark)
        return None


class RepP(Patt):
    """Greedy repetition [lo, hi]; a zero-width match counts once then stops."""
    def __init__(self, p, lo: int = 0, hi: int | None = None) -> None:
        super().__init__()
        self.p, self.lo, self.hi = p, lo, hi

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        caps, p, n = [], pos, 0
        while self.hi is None or n < self.hi:
            mark = ctx.checkpoint()
            if (r := ctx.run(self.p, s, p)) is None:
                ctx.rollback(mark)
                break
            np_, cs = r
            if np_ == p:  # zero-width: count it once, stop
                caps += cs
                n += 1
                break
            p, caps = np_, caps + cs
            n += 1
        return (p, caps) if n >= self.lo else None


class NotP(Patt):
    def __init__(self, p) -> None:
        super().__init__()
        self.p = p

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        mark = ctx.checkpoint()
        r = ctx.run(self.p, s, pos)
        if r is not None:
            ctx.rollback(mark)
            return None
        return pos, []


class AndP(Patt):
    def __init__(self, p) -> None:
        super().__init__()
        self.p = p

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        return (pos, []) if ctx.run(self.p, s, pos) is not None else None


class CapP(Patt):
    """{ p } -- capture the matched substring."""
    def __init__(self, p) -> None:
        super().__init__()
        self.p = p

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        if (r := ctx.run(self.p, s, pos)) is None:
            return None
        p, cs = r
        _record(ctx, pos, p, s[pos:p])
        return p, cs + [s[pos:p]]


class CsP(Patt):
    """{~ p ~} -- substitution: whole match with captures spliced in."""
    def __init__(self, p) -> None:
        super().__init__()
        self.p = p

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        rec: list = []
        ctx.recorders.append(rec)
        try:
            r = ctx.run(self.p, s, pos)
        finally:
            ctx.recorders.pop()
        if r is None:
            return None
        p, cs = r
        rec.sort()
        out, cur = [], pos
        for a, b, t in rec:
            if a > cur:
                out.append(s[cur:a])
            out.append(t)
            cur = max(cur, b)
        if cur < p:
            out.append(s[cur:p])
        if not rec and not cs:
            out = [s[pos:p]]
        return p, ["".join(out)]


class CtP(Patt):
    """{| p |} / p -> {} -- table capture: inner caps become one list."""
    def __init__(self, p) -> None:
        super().__init__()
        self.p = p

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        if (r := ctx.run(self.p, s, pos)) is None:
            return None
        p, cs = r
        return p, [list(cs)]


class CpP(Patt):
    """{} -- capture the current position."""
    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        return pos, [pos]


class ValP(Patt):
    """$x -- match empty, capture a constant."""
    def __init__(self, value: Any) -> None:
        super().__init__()
        self.value = value

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        return pos, [self.value]


class FuncP(Patt):
    """p -> f : apply f to p's captures (or the whole match if none)."""
    def __init__(self, p, fn: Callable) -> None:
        super().__init__()
        self.p, self.fn = p, fn

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        if (r := ctx.run(self.p, s, pos)) is None:
            return None
        p, cs = r
        res = self.fn(*(cs if cs else [s[pos:p]]))
        if res is None:
            _record(ctx, pos, p, "")
            return p, [None]  # `-> tonil` yields a present nil child
        if isinstance(res, tuple):
            _record(ctx, pos, p, "".join(str(x) for x in res))
            return p, list(res)
        _record(ctx, pos, p, str(res))
        return p, [res]


class CmtP(Patt):
    """p => f : match-time capture (LPeg Cmt). Never memoized."""
    _nomemo = True

    def __init__(self, p, fn: Callable) -> None:
        super().__init__()
        self.p, self.fn = p, fn

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        if (r := ctx.run(self.p, s, pos)) is None:
            return None
        end, cs = r
        res = self.fn(s, end, *(cs if cs else [s[pos:end]]))
        if not res:
            return None
        return (end, cs) if res is True else (res, cs)


class FoldP(Patt):
    """p ~> f : fold the capture list into a single value."""
    def __init__(self, p, fn: Callable) -> None:
        super().__init__()
        self.p, self.fn = p, fn

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        if (r := ctx.run(self.p, s, pos)) is None:
            return None
        p, cs = r
        return p, [self.fn(*cs)]


class GroupP(Patt):
    """{:name: p :} -- named group; a capture-less p captures its whole match."""
    def __init__(self, name: str | None, p) -> None:
        super().__init__()
        self.name, self.p = name, p

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        if (r := ctx.run(self.p, s, pos)) is None:
            return None
        p, cs = r
        if self.name is not None:
            ctx.names.setdefault(self.name, []).append(cs if cs else [s[pos:p]])
        return p, cs


class BackP(Patt):
    """=name -- re-capture the most recent named-group values."""
    def __init__(self, name: str) -> None:
        super().__init__()
        self.name = name

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        if not (stack := ctx.names.get(self.name)):
            return None
        return pos, list(stack[-1])


class EqBackP(Patt):
    """=name -- LPeg equalcap: match text equal to the named capture."""
    def __init__(self, name: str) -> None:
        super().__init__()
        self.name = name

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        if not (stack := ctx.names.get(self.name)):
            return None
        val = "".join(str(x) for x in stack[-1])
        # LPeg equalcap: an empty capture matches the empty string
        return (pos + len(val), []) if s.startswith(val, pos) else None


class ThrowP(Patt):
    """Fatal error label."""
    def __init__(self, label: str) -> None:
        super().__init__()
        self.label = label

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        raise Throw(self.label, pos)


class NodeP(Patt):
    """`<==` node rule: Node(tag, pos, endpos, children) around p."""
    def __init__(self, tag: str, p, with_pos: bool = True, with_end: bool = True):
        super().__init__()
        self.tag, self.p = tag, p
        self.with_pos, self.with_end = with_pos, with_end

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        if (r := ctx.run(self.p, s, pos)) is None:
            return None
        p, cs = r
        node = Node(self.tag, pos if self.with_pos else None,
                    p if self.with_end else None, list(cs))
        return p, [node]


class V(Patt):
    """Rule reference, resolved at match time (forward references OK)."""
    def __init__(self, name: str) -> None:
        super().__init__()
        self.name = name

    def match(self, s, pos, ctx):
        """Implement match with the module's explicit API and failure semantics."""
        if (q := ctx.rules.get(self.name)) is None:
            raise Throw("UndefinedRule_" + self.name, pos)
        return ctx.run(q, s, pos)


def run(patt: Patt, source: str, rules=None, defs=None):
    """Match -> (value, None, None) on success, (None, label, pos) on failure.
    Mirrors lpegrex's `ast, errlabel, errpos` triple."""
    import sys
    if sys.getrecursionlimit() < 100_000:
        sys.setrecursionlimit(100_000)
    ctx = Ctx(rules or {}, defs)
    try:
        r = ctx.run(patt, source, 0)
    except Throw as t:
        return None, t.label, t.pos
    if r is None:
        return None, "Fail", 0
    p, cs = r
    if cs:
        return (cs[0] if len(cs) == 1 else cs), None, None
    return p, None, None
