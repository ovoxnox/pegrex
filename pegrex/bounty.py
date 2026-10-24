"""
bounty - autonomous bug-bounty agent slice

Given a vulnerable function and a sink name: (1) discover the guard that
gates the sink, (2) solve the guard constraints for a concrete payload
(engine), (3) minimize the payload's guard by dropping redundant
atoms while the witness stays feasible. Every stage reports honestly:
no guard or infeasible constraints -> unknown, never a fake PoC."""

from __future__ import annotations

import re

from .ir import lower_condition
from .linsolve import LinearBackend, atoms_of

DEFAULT_LB = LinearBackend()


_GUARD = {
    "python": r"if\s+(.+?):\s*\n\s*{S}\s*\(",
    "go": r"if\s+(.+?)\s*\{[^{}]*?{S}\s*\(",
    "rust": r"if\s+(.+?)\s*\{[^{}]*?{S}\s*\(",
    "javascript": r"if\s*\((.+?)\)\s*\{[^{}]*?{S}\s*\(",
    "typescript": r"if\s*\((.+?)\)\s*\{[^{}]*?{S}\s*\(",
    "solidity": r"if\s*\((.+?)\)\s*\{[^{}]*?{S}\s*\(",
    "kotlin": r"if\s*\((.+?)\)\s*\{[^{}]*?{S}\s*\(",
    "zig": r"if\s*\((.+?)\s*[^{}]*?\b{S}\s*\(",
    "julia": r"if\s+(.+?)\s*\{[^{}]*?{S}\s*\(",
}


def discover(src, sink_name, lang="python"):
    """Find the guard expression gating a call to sink_name."""
    pat = _GUARD.get(lang, _GUARD["python"]).replace("{S}", re.escape(sink_name))
    m = re.search(pat, src, re.S)
    return m.group(1).strip() if m else None


def solve_payload(guard_text, lb=None):
    """Concrete input satisfying the guard (the payload)."""
    lb = lb or DEFAULT_LB
    try:
        atoms = atoms_of(lower_condition(guard_text))
    except Exception:
        return None
    model = lb.learn(atoms)
    if not model.feasible():
        return None
    return model.model() or None


def minimize(guard_text, payload, lb=None):
    """Drop atoms one at a time; keep a witness equal to the payload."""
    lb = lb or DEFAULT_LB
    atoms = atoms_of(lower_condition(guard_text))
    minimal = list(atoms)
    for a in list(minimal):
        trial = [x for x in minimal if x != a]
        m = lb.learn(trial)
        if m.feasible() and m.model() == payload:
            minimal = trial
    return minimal


def run(src, sink_name, lb=None, lang="python"):
    """Full chain: discover -> solve -> minimize. Unknown when any stage
    cannot proceed -- never a fake PoC."""
    guard = discover(src, sink_name, lang=lang)
    if guard is None:
        return {"status": "unknown", "reason": f"no guard found for {sink_name}"}
    payload = solve_payload(guard, lb)
    if not payload:
        return {"status": "unknown",
                "reason": "guard constraints infeasible or opaque",
                "guard": guard}
    core = minimize(guard, payload, lb)
    return {"status": "poc", "guard": guard, "payload": payload,
            "minimal_guard_atoms": core,
            "removed": len(atoms_of(lower_condition(guard))) - len(core)}
