"""lpegc.parser - lexical helpers and prelude patterns."""

from __future__ import annotations

import re
from typing import Any, Callable

from .. import peg
from ..peg import (AndP, AltP, AnyP, BackP, CapP, CmtP, CpP, CsP, CtP, Eps,
                  EqBackP, FoldP, FuncP, GroupP, Lit, NodeP, NotP, RepP,
                  SeqP, SetP, ThrowP, ValP, V)

NL = chr(10)


def _kids(x):
    """Mutable child list of a capture: Node -> children; list -> itself;
    scalar -> a fresh throwaway (folds never mutate scalars)."""
    if isinstance(x, peg.Node):
        return x.children
    if isinstance(x, list):
        return x
    return [x]


def _foldleft(*caps):
    it = iter(caps)
    lhs = next(it)
    for rhs in it:
        k = _kids(rhs)
        # memo reuse must not re-fold
        if not k or k[0] is not lhs:
            k.insert(0, lhs)
        lhs = rhs
    return lhs


def _foldright(*caps):
    caps = list(caps)
    first, lhs = caps[0], caps[0]
    for rhs in caps[1:]:
        _kids(lhs).append(rhs)
        lhs = rhs
    return first


def _rfoldleft(*caps):
    caps = list(caps)
    first, rhs = caps[0], caps[0]
    for lhs in caps[1:]:
        k = _kids(rhs)
        if not k or k[0] is not lhs:
            k.insert(0, lhs)
        rhs = lhs
    return first


def _rfoldright(*caps):
    it = iter(caps)
    lhs = next(it)
    for rhs in it:
        k = _kids(rhs)
        if not k or k[-1] is not lhs:
            k.append(lhs)
        lhs = rhs
    return lhs


def _tochar(s, base=None):
    return chr(int(s) if base is None else int(s, int(base)))


def _toutf8char(s, base=None):
    return chr(int(s) if base is None else int(s, int(base)))


def _tonumber(s):
    try:
        return int(s, 0)
    except ValueError:
        pass
    try:
        return int(s)
    except ValueError:
        return float(s)


def _toemptytable(*_):
    return []


PRELUDE: dict[str, Any] = {
    "nl": Lit(NL), "ca": Lit(chr(7)), "cb": Lit(chr(8)), "ct": Lit(chr(9)),
    "cn": Lit(NL), "cv": Lit(chr(11)), "cf": Lit(chr(12)), "cr": Lit(chr(13)),
    "sp": SetP([" ", NL, chr(13), chr(9), chr(12), chr(11)]),
    "utf8": SetP([(chr(0), chr(0x7F)), (chr(0xC2), chr(0xFD))]),
    "utf8seq": SetP([(chr(0xC2), chr(0xFD))]),
    "ascii": SetP([(chr(0), chr(0x7F))]),
    "a": SetP([("a", "z"), ("A", "Z")]),
    "c": SetP([(chr(0), chr(31)), chr(127)]),
    "d": SetP([("0", "9")]),
    "g": SetP([(chr(33), chr(126))]),
    "l": SetP([("a", "z")]),
    "p": SetP([(chr(33), chr(47)), (chr(58), chr(64)),
               (chr(91), chr(96)), (chr(123), chr(126))]),
    "s": SetP([chr(9), chr(10), chr(11), chr(12), chr(13), chr(32)]),
    "u": SetP([("A", "Z")]),
    "w": SetP([("0", "9"), ("a", "z"), ("A", "Z")]),
    "x": SetP([("0", "9"), ("a", "f"), ("A", "F")]),
    "tonil": lambda *_: None,
    "totrue": lambda *_: True,
    "tofalse": lambda *_: False,
    "toemptytable": _toemptytable,
    "tonumber": _tonumber,
    "tochar": _tochar,
    "toutf8char": _toutf8char,
    "foldleft": _foldleft,
    "foldright": _foldright,
    "rfoldleft": _rfoldleft,
    "rfoldright": _rfoldright,
}
for _c in "acdglpsuwx":
    # resolved lazily as complement below
    PRELUDE[_c.upper()] = None


_NAME_START = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_"
_NAME_CONT = _NAME_START + "0123456789"
_PUNCT = set("!\"#$%&'()*+,-./:;<=>?@[\\]^`{|}~")
