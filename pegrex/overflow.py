"""
overflow — integer-overflow semantics per language

║  A u8 in Rust-debug panics; in Rust-release wraps; in C it is UB; in    
║  Solidity it reverts. The same path constraint gets a different verdict 
║  per language mode. Windows are exact FM projections (every companion  
║  variable eliminated, never zeroed) -- 'ok' is therefore sound;  
║  'possible' is a may-verdict, reported."""

from __future__ import annotations

from .linsolve import LinearBackend, _combine, _unit_bounds

# mode -> consequence of exceeding the type's range
MODES = {
    "rust_debug":   "panic-possible",
    "rust_release": "wraps",
    "c":            "undefined-behavior",
    "solidity":     "revert-possible",
}
# type -> (lo, hi) inclusive
RANGES = {
    "u8": (0, 255), "i8": (-128, 127),
    "u16": (0, 65535), "i16": (-32768, 32767),
    "u32": (0, 4294967295), "i32": (-2147483648, 2147483647),
    "u256": (0, 2**256 - 1), "i256": (-(2**255), 2**255 - 1),
}

DEFAULT_LB = LinearBackend()


def window(model, var):
    """Sound integer window for var: Fourier-Motzkin every other
    variable out (full elimination, same primitives linsolve._eliminate
    uses), then read the exact bound off the fully-reduced single-variable
    system. None = unbounded."""
    ineqs = [(a.cd(), a.k) for a in model.src if a.op == "<="]
    drop = sorted({v for coeffs, _ in ineqs for v in coeffs} - {var})
    for d in drop:
        highs, lows, others = _unit_bounds(ineqs, d)
        new = list(others)
        for h in highs:
            for l in lows:
                new.append(_combine(h, l))
        ineqs = new
    lo, hi = None, None
    for coeffs, k in ineqs:
        c = coeffs.get(var, 0)
        if c == 0:
            continue   # constant atom; contradictions are
                       # already caught by model.feasible_flag
        b = k / c
        if c > 0:
            hi = b if hi is None else min(hi, b)
        else:
            lo = b if lo is None else max(lo, b)
    return lo, hi


def check_overflow(atoms, types, mode, lb=None) -> dict:
    """Per-var verdicts. Typed vars get an overflow verdict in the given
    language mode; untyped vars are 'untracked' -- refused, not guessed."""
    lb = lb or DEFAULT_LB
    if mode not in MODES:
        raise ValueError(f"overflow: unknown mode {mode!r}")
    model = lb.learn(list(atoms))
    out = {}
    for var in sorted({v for a in atoms for v in __import__("re").findall(r"[A-Za-z_]\w*", a)}):
        if var not in types:
            out[var] = {"status": "untracked"}
            continue
        if types[var] not in RANGES:
            out[var] = {"status": "unknown-type", "type": types[var]}
            continue
        tlo, thi = RANGES[types[var]]
        lo, hi = window(model, var)
        in_range = (lo is not None and hi is not None
                    and lo >= tlo and hi <= thi)
        out[var] = {
            "status": "ok" if in_range else MODES[mode],
            "type": types[var],
            "window": [None if lo is None else int(lo),
                       None if hi is None else int(hi)],
            "range": [tlo, thi],
        }
    return out
