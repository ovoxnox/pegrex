"""lpegc.diagnostics - grammar-text error types."""

from __future__ import annotations

import re
from typing import Any, Callable

from .. import peg
from ..peg import (AndP, AltP, AnyP, BackP, CapP, CmtP, CpP, CsP, CtP, Eps,
                  EqBackP, FoldP, FuncP, GroupP, Lit, NodeP, NotP, RepP,
                  SeqP, SetP, ThrowP, ValP, V)

NL = chr(10)


class GrammarError(Exception):
    pass


class _Expected(GrammarError):
    def __init__(self, msg: str, text: str, pos: int) -> None:
        self.pos = pos
        line = text.count(NL, 0, pos) + 1
        col = pos - (text.rfind(NL, 0, pos) + 1) + 1
        super().__init__(f"grammar syntax error at L{line}:C{col}: {msg}")


class _NoPattern(_Expected):
    """No pattern can start here — sequences treat this as a normal end."""
