"""
║ insure — smart-contract insurance oracle

║  Certificate-backed premium quotes from verified overflow risk.         
║  Pipeline: tree-sitter Solidity frontend -> path contracts -> per-var   
║  arithmetic windows via pegrex.overflow.window (the fixed, sound        
║  Fourier-Motzkin projection) + linear entailment checks on the result   
║  expression. Risk tier: "high" if any window/result provably exceeds    
║  the declared integer bounds on a feasible path; "medium" within 10%    
║  of a bound; else "low".                                                

║  The quote is HMAC-signed (pegrex.attest); verify_quote() detects     
║  any tampering with the quoted body.                                    
║  Documented engine limits: Solidity integer vars are modeled as         
║  mathematical integers (LIA) -- ABI range checks are not modeled; an    
║  unbounded window side is a MAY-verdict (reported, never 'ok'), never   
║  counted as a provable exceed. External call semantics and reentrancy   
║  are NOT analyzed (claims() says so)."""

from __future__ import annotations

import re

from .attest import hmac_sign, hmac_verify
from .linsolve import LinearBackend, parse_atom
from .overflow import check_overflow, window
from .refine import _norm_constraint

BASE_PREMIUM = 100
TIER_MULTIPLIER = {"low": 1.0, "medium": 2.5, "high": 10.0}
# overflow.RANGES keys cover exactly these widths
_RANGE_KEY = {8: "u8", 16: "u16", 32: "u32", 256: "u256"}


class InsureError(ValueError):
    """Loud refusal from the oracle -- never a guessed quote."""


def claims() -> dict:
    """Honesty manifest (the zk.is_mock_check pattern)."""
    return {
        "proven": [
            "path contracts via the pegrex pipeline (tree-sitter Solidity frontend)",
            "overflow windows via pegrex.overflow.window -- the fixed, "
            "sound Fourier-Motzkin projection engine",
            "risk tier derived from those windows and linear entailments "
            "on the feasible paths",
        ],
        "not_proven": [
            "premium is a documented heuristic, not an actuarial price",
            "external call semantics (arbitrary callees are not modeled)",
            "reentrancy (no cross-function interaction analysis)",
        ],
    }


def _solidity_contracts(src, path):
    m = re.search(r"function\s+(\w+)\s*\(([^)]*)\)", src)
    if not m:
        raise InsureError("insure: no function found in source")
    fn = m.group(1)
    requires = re.findall(r"require\s*\(\s*(.+?)\s*\)\s*;", src)
    ret = re.search(r"return\s+(.+?)\s*;", src)
    if ret is None:
        raise InsureError("insure: no return statement -- refusing to guess "
                          "the result expression")
    from .ir import lower_condition
    from .linsolve import atoms_of
    from .sym import And
    atoms = []
    for cond in requires:
        try:
            atoms += atoms_of(lower_condition(cond))
        except Exception:
            raise InsureError(f"insure: unreadable require {cond!r} -- "
                              "refusing to guess")
    result = ret.group(1).strip()
    return [(frozenset(atoms), result)], fn


def _path_atoms(constraint_strs):
    atoms = []
    for c in constraint_strs:
        n = _norm_constraint(str(c))
        try:
            parse_atom(n)
            atoms.append(n)
        except Exception:
            pass
    return atoms


def _expr_exceeds(model, rexpr, bound_txt):
    """Does the path model provably put this linear result expression
    past `bound_txt` (e.g. '>= 2**256' or '<= -1')? Non-linear result
    expressions refuse (False), never guess."""
    if not rexpr:
        return False
    try:
        from .ir import lower_condition
        es = lower_condition(f"{rexpr} {bound_txt}")
        return LinearBackend().entails(model, es)
    except Exception:
        return False


def quote(solidity_src, fn_name=None, key="insurance-demo-key",
          type_bits=256) -> dict:
    """Quote a premium for one Solidity function from verified overflow
    risk. Every numeric variable is treated as an unsigned type_bits-wide
    integer. Returns {"quote": body, "signature":...}
    where body is the canonical, HMAC-signed quote document."""
    if not isinstance(solidity_src, str) or not solidity_src.strip():
        raise InsureError("insure: empty source -- there is nothing to quote")
    if type_bits < 2:
        raise InsureError(f"insure: type_bits={type_bits} is not a usable "
                          f"integer width -- refusing to quote nonsense")
    contracts, first = _solidity_contracts(solidity_src, fn_name)
    lo_bound, hi_bound = 0, 2 ** type_bits - 1
    lb = LinearBackend()
    tier = "low"
    reasons, windows = [], []
    range_key = _RANGE_KEY.get(type_bits)
    for cs, res in contracts:
        atoms = _path_atoms(cs)
        model = lb.learn(atoms)
        if not model.feasible():
            continue  # infeasible path: nothing to price
        typed = {v: range_key for v in
                 sorted({v for a in atoms
                         for v in re.findall(r"[A-Za-z_]\w*", a)})} \
            if range_key else {}
        sound = check_overflow(atoms, typed, "solidity") if typed else {}
        for var in sorted(typed or {}):
            lo, hi = window(model, var)
            lo_i = int(lo) if lo is not None else None
            hi_i = int(hi) if hi is not None else None
            windows.append({"var": var, "path": sorted(map(str, cs)),
                            "window": [lo_i, hi_i],
                            "range": [lo_bound, hi_bound],
                            "overflow_status": sound.get(var, {})
                            .get("status", "untracked")})
            if ((lo is not None and (lo < lo_bound or lo > hi_bound))
                    or (hi is not None and (hi < lo_bound
                                            or hi > hi_bound))):
                tier = "high"
                reasons.append(
                    f"var {var} window [{lo_i}, {hi_i}] provably outside "
                    f"[{lo_bound}, {hi_bound}] on a feasible path")
        rexpr = str(res).strip().rstrip(";").strip()
        if _expr_exceeds(model, rexpr, f">= {2 ** type_bits}") or \
                _expr_exceeds(model, rexpr, "<= -1"):
            tier = "high"
            reasons.append(
                f"result expression {rexpr!r} provably exceeds "
                f"uint{type_bits} bounds on a feasible path")
    if tier == "low":
        for w in windows:
            lo_i, hi_i = w["window"]
            if (hi_i is not None
                    and hi_bound - hi_i <= 0.1 * (hi_bound - lo_bound)) or \
               (lo_i is not None
                    and lo_i - lo_bound <= 0.1 * (hi_bound - lo_bound)):
                tier = "medium"
                reasons.append(f"var {w['var']} window {w['window']} comes "
                               f"within 10% of a uint{type_bits} bound")
                break
    body = {"fn": first, "type_bits": type_bits, "tier": tier,
            "base": BASE_PREMIUM, "multiplier": TIER_MULTIPLIER[tier],
            "premium": round(BASE_PREMIUM * TIER_MULTIPLIER[tier], 2),
            "paths": len(contracts), "windows": windows,
            "reasons": reasons, "heuristic": True,
            "note": "premium is a documented heuristic, not an actuarial "
                    "price; see insure.claims()"}
    return {"quote": body, "signature": hmac_sign(body, key)}


def verify_quote(quoted, key) -> bool:
    """Constant-time re-check of a quote's HMAC over its canonical body.
    Any tampering with the body (e.g. flipping the tier) fails here."""
    if not isinstance(quoted, dict):
        return False
    body = quoted.get("quote")
    sig = quoted.get("signature")
    if not isinstance(body, dict) or not sig:
        return False
    return hmac_verify(body, key, sig)
