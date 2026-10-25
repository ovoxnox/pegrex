"""
tv - three-valued results, first-class

PROVED / REFUTED / UNKNOWN are the only verdicts the engine ever emits.
`wrap` converts ANY engine result (verify_patch/chain/refine shaped) into
the tri-valued form. The invariant is certified: an absent, crashed, or
unparseable result is UNKNOWN -- never presented as proved. "No path found"
is not "verified"."""

from __future__ import annotations

PROVED = "proved"
REFUTED = "refuted"
UNKNOWN = "unknown"


def tri(verified) -> str:
    """bool | None | anything-else -> verdict."""
    if verified is True:
        return PROVED
    if verified is False:
        return REFUTED
    return UNKNOWN


def wrap(result) -> dict:
    """Normalize any engine result dict into tri-valued form.

    Never raises: a crashed, missing, or malformed result is UNKNOWN with
    the reason attached."""
    if result is None:
        return {"verdict": UNKNOWN, "reason": "no result produced"}
    if not isinstance(result, dict):
        return {"verdict": UNKNOWN, "reason": f"unexpected result type "
                                               f"{type(result).__name__}"}
    try:
        v = result.get("verified", result.get("status"))
    except Exception as e:
        return {"verdict": UNKNOWN, "reason": f"unreadable result: {e}"}
    verdict = tri(v)
    if (v is False and not result.get("counterexample")
            and ("counterexample" in result or "distinguishing" in result)):
        # Legacy verify_patch uses verified=False both for a confirmed
        # counterexample and for an undecided difference. Match CoreEngine:
        # only the former is REFUTED.
        verdict = UNKNOWN
    if verdict == UNKNOWN and isinstance(v, str):
        # conservative string mapping: refusal-family statuses are REFUTED;
        # NOTHING string-shaped is ever upgraded to PROVED
        if v.strip().lower() in ("refused", "violated", "refuted", "rejected",
                                 "false", "dropped"):
            verdict = REFUTED
    out = dict(result)
    out["verdict"] = verdict
    if verdict == UNKNOWN and "reason" not in out:
        out["reason"] = "engine could not decide (fragment limit, timeout, " \
                        "or infeasible evidence)"
    return out


def wrap_fn(fn, *args, **kwargs) -> dict:
    """Run fn under the three-valued discipline: exceptions are UNKNOWN,
    never a crash and never a silent pass."""
    try:
        return wrap(fn(*args, **kwargs))
    except Exception as e:
        return {"verdict": UNKNOWN, "reason":
                f"{type(e).__name__}: {str(e)[:140]}"}


def check_never_claims_unknown_as_proved(samples) -> list:
    """Audit helper: every sample wrapped must not claim PROVED unless the
    underlying verdict was True. Returns violations (must be [])."""
    bad = []
    for s in samples:
        w = wrap(s)
        if w["verdict"] == PROVED and not (isinstance(s, dict)
                                           and s.get("verified") is True):
            bad.append({"sample": str(s)[:60], "verdict": w["verdict"]})
    return bad
