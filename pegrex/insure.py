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


def _require_key(key) -> None:
    if not isinstance(key, (str, bytes)) or not key:
        raise InsureError(
            "insure: an explicit non-empty HMAC key is required; demo defaults are disabled")


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


def _function_body(src, opening):
    """Return a brace-balanced function body, honoring strings and comments."""
    depth = 0
    index = opening
    quote = None
    while index < len(src):
        char = src[index]
        pair = src[index:index + 2]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
        elif pair == "//":
            index = src.find("\n", index)
            if index < 0:
                break
        elif pair == "/*":
            end = src.find("*/", index + 2)
            if end < 0:
                raise InsureError("insure: unterminated comment")
            index = end + 1
        elif char in {'"', "'"}:
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return src[opening + 1:index]
        index += 1
    raise InsureError("insure: unterminated function body")


def _solidity_contracts(src, fn_name):
    matches = list(re.finditer(
        r"function\s+(\w+)\s*\(([^)]*)\)[^{]*\{", src, re.S))
    if fn_name is not None:
        matches = [match for match in matches if match.group(1) == fn_name]
    if not matches:
        raise InsureError(f"insure: requested function {fn_name!r} was not found")
    if len(matches) != 1:
        raise InsureError(
            "insure: multiple functions are present; fn_name is required for a bounded quote")
    match = matches[0]
    fn = match.group(1)
    parameters = re.findall(r"\b(?:u?int)(?:8|16|32|64|128|256)?\s+(\w+)",
                            match.group(2))
    body = _function_body(src, match.end() - 1)
    requires = re.findall(r"require\s*\(\s*(.+?)\s*\)\s*;", body, re.S)
    returns = re.findall(r"return\s+(.+?)\s*;", body, re.S)
    if len(returns) != 1:
        raise InsureError(
            "insure: exactly one return is required; refusing to guess multiple-return semantics")
    from .ir import lower_condition
    from .linsolve import atoms_of
    atoms = []
    for cond in requires:
        try:
            atoms += atoms_of(lower_condition(cond))
        except Exception as error:
            raise InsureError(f"insure: unreadable require {cond!r} -- "
                              "refusing to guess") from error
    return [(frozenset(atoms), returns[0].strip())], fn, parameters


def _path_atoms(constraint_strs):
    atoms, unknowns = [], []
    for constraint in constraint_strs:
        normalized = _norm_constraint(str(constraint))
        try:
            parse_atom(normalized)
            atoms.append(normalized)
        except Exception as error:
            unknowns.append(
                f"constraint {constraint!r} is outside the supported linear fragment: "
                f"{type(error).__name__}")
    return atoms, unknowns


def _expr_decision(model, rexpr, condition):
    """Return True/False only for a solver decision, or None when unsupported."""
    if not rexpr:
        return None
    try:
        from .ir import lower_condition
        expression = lower_condition(condition)
        return LinearBackend().entails(model, expression)
    except Exception:
        return None


def _expr_exceeds(model, rexpr, bound_txt):
    return _expr_decision(model, rexpr, f"({rexpr}) {bound_txt}")


def _expr_within(model, rexpr, maximum):
    return _expr_decision(
        model, rexpr, f"({rexpr}) >= 0 and ({rexpr}) <= {maximum}")


def quote(solidity_src, fn_name=None, key=None, type_bits=256) -> dict:
    """Return a signed, source-bounded overflow-risk quote.

    Missing constraints, unsupported expressions, and unbounded windows produce
    UNKNOWN rather than a low-risk quote. A confirmed bound violation may retain
    a conservative high-risk premium even when other evidence is incomplete.
    """
    _require_key(key)
    if not isinstance(solidity_src, str) or not solidity_src.strip():
        raise InsureError("insure: empty source -- there is nothing to quote")
    if not isinstance(type_bits, int) or type_bits < 2:
        raise InsureError(f"insure: type_bits={type_bits} is not a usable integer width")
    contracts, first, parameters = _solidity_contracts(solidity_src, fn_name)
    lo_bound, hi_bound = 0, 2 ** type_bits - 1
    lb = LinearBackend()
    reasons, windows, unknowns = [], [], []
    range_key = _RANGE_KEY.get(type_bits)
    if range_key is None:
        unknowns.append(f"uint{type_bits} is outside registered overflow ranges")
    if not parameters:
        unknowns.append("no supported integer parameters were extracted")
    confirmed_high = False
    feasible_paths = 0
    for constraints, result in contracts:
        atoms, parse_unknowns = _path_atoms(constraints)
        unknowns.extend(parse_unknowns)
        model = lb.learn(atoms)
        if not model.feasible():
            continue
        feasible_paths += 1
        typed = {name: range_key for name in parameters} if range_key else {}
        sound = check_overflow(atoms, typed, "solidity") if typed else {}
        for var in parameters:
            lo, hi = window(model, var)
            lo_i = int(lo) if lo is not None else None
            hi_i = int(hi) if hi is not None else None
            windows.append({"var": var, "path": sorted(map(str, constraints)),
                            "window": [lo_i, hi_i], "range": [lo_bound, hi_bound],
                            "overflow_status": sound.get(var, {}).get("status", "untracked")})
            if lo is None or hi is None:
                unknowns.append(f"variable {var} has an unbounded window")
            if ((lo is not None and (lo < lo_bound or lo > hi_bound))
                    or (hi is not None and (hi < lo_bound or hi > hi_bound))):
                confirmed_high = True
                reasons.append(
                    f"var {var} window [{lo_i}, {hi_i}] provably outside "
                    f"[{lo_bound}, {hi_bound}] on a feasible path")
        expression = str(result).strip().rstrip(";").strip()
        exceeds_high = _expr_exceeds(model, expression, f">= {2 ** type_bits}")
        exceeds_low = _expr_exceeds(model, expression, "<= -1")
        if exceeds_high is True or exceeds_low is True:
            confirmed_high = True
            reasons.append(
                f"result expression {expression!r} provably exceeds uint{type_bits} bounds")
        if exceeds_high is None or exceeds_low is None:
            unknowns.append(f"result expression {expression!r} is outside the supported fragment")
        else:
            within = _expr_within(model, expression, hi_bound)
            if within is not True:
                unknowns.append(
                    f"result expression {expression!r} is not proved within uint{type_bits} bounds")
    if not feasible_paths:
        unknowns.append("no feasible source path was proved")
    unknowns = sorted(set(unknowns))
    if confirmed_high:
        tier = "high"
    elif unknowns:
        tier = "unknown"
    else:
        tier = "low"
        for row in windows:
            lo_i, hi_i = row["window"]
            span = hi_bound - lo_bound
            if ((hi_i is not None and hi_bound - hi_i <= 0.1 * span)
                    or (lo_i is not None and lo_i - lo_bound <= 0.1 * span)):
                tier = "medium"
                reasons.append(
                    f"var {row['var']} window {row['window']} comes within 10% of a bound")
                break
    multiplier = TIER_MULTIPLIER.get(tier)
    premium = round(BASE_PREMIUM * multiplier, 2) if multiplier is not None else None
    status = "unknown" if tier == "unknown" else ("partial" if unknowns else "ok")
    body = {"fn": first, "type_bits": type_bits, "tier": tier, "status": status,
            "base": BASE_PREMIUM, "multiplier": multiplier, "premium": premium,
            "paths": len(contracts), "feasible_paths": feasible_paths,
            "windows": windows, "reasons": reasons, "unknowns": unknowns,
            "heuristic": True,
            "note": "premium is a documented heuristic, not an actuarial price; "
                    "UNKNOWN tiers have no premium"}
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
