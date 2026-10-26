"""
loops

║  Closed-form summaries for counting loops. Path formulas bound loops; 
║  these verify every iteration count at once. Textbook pattern:   
║      while i <= n:  s = s + i;  i = i + 1  ->   s = n*(n+1)  
║  Language-agnostic: works on rendered assignment strings."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .sym import Sym, Add, Sub, Mul, Floordiv, const

_STEP = re.compile(r"^([A-Za-z_]\w*)=\1\+(\d+)$")
_ACC = re.compile(r"^([A-Za-z_]\w*)=\1\+([A-Za-z_]\w*)$")


@dataclass(frozen=True)
class CountingLoop:
    index: str
    accum: str
    init_index: int
    init_accum: int
    step: int = 1


def detect(assignments: list[str], inits: dict[str, int]) -> CountingLoop | None:
    """Implement detect with the module's explicit API and failure semantics."""
    step = acc = None
    for a in (x.replace(" ", "") for x in assignments):
        if (m := _STEP.match(a)):
            step = (m.group(1), int(m.group(2)))
        elif (m := _ACC.match(a)):
            acc = (m.group(1), m.group(2))
    if not step or not acc or step[1] != 1 or acc[1] != step[0]:
        return None
    if step[0] not in inits or acc[0] not in inits:
        return None
    return CountingLoop(index=step[0], accum=acc[0],
                        init_index=inits[step[0]], init_accum=inits[acc[0]])


def closed_form(lp: CountingLoop, bound) -> object:
    """Accumulator exit value: Gauss sum, exact (the numerator 2*s0 +
    k*(i0 + bound) is always even -- consecutive integers).  The division
    is the point: evidence runs caught the previous form omitting
    it -- (n * (n + 1)) is twice sum(1..n).
    Valid for bound >= init_index - 1 (k >= 0 iterations); below that the
    loop runs zero times and the result is init_accum, which the form does
    not model -- callers must state that precondition, not pretend."""
    b = Sym(str(bound))
    k = Sub(b, const(lp.init_index - 1))       # iteration count
    if lp.init_index == 1 and lp.init_accum == 0:
        return Floordiv(Mul(b, Add(b, const(1))), const(2))
    num = Add(Mul(const(2), const(lp.init_accum)),
              Mul(k, Add(const(lp.init_index), b)))
    return Floordiv(num, const(2))


def contract_closed_form(lp: CountingLoop, bound) -> dict[str, str]:
    """Implement contract closed form with the module's explicit API and failure semantics."""
    return {"index_exit": f"{lp.index} = ({bound} + 1)",
            "result": str(closed_form(lp, bound))}
