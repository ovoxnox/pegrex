"""
rabk — termination certificates for linear loops 

║  Ranking-function templates over (bound, counter) pairs, discharged by  
║  the entailment engine -- never assumed. Complements the recursion  
║  "unbounded" heuristic with positive proofs of termination.             
║  Template: R = bound - counter + 1  (resp. reversed for descending),    
║  requires step ±1 on the counter and guard |= R >= 1."""

from __future__ import annotations

import re

from .ir import lower_condition
from .linsolve import LinearBackend, atoms_of

_STEP = re.compile(r"^([A-Za-z_]\w*)=\1([+-]\d+)$")

DEFAULT_BACKEND = LinearBackend()


def deltas_of(assignments: list[str]) -> dict:
    """{var: per-iteration constant delta} from rendered 'v=v+k' strings."""
    out = {}
    for a in (x.replace(" ", "") for x in assignments):
        m = _STEP.match(a)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


def find_ranking(guard_text: str, deltas: dict, lb=None) -> str | None:
    """A ranking function R proven by entailment, or None (honest refusal).

    Positive step:  R = bound - counter + 1, needs guard |= R >= 1.
    Negative step:  R = counter - bound + 1, same discharge."""
    lb = lb or DEFAULT_BACKEND
    try:
        guard_atoms = atoms_of(lower_condition(guard_text))
    except Exception:
        return None
    model = lb.learn(guard_atoms)
    if not model.feasible():
        return None
    guard_vars = set()
    for a in guard_atoms:
        guard_vars |= set(__import__("re").findall(r"[A-Za-z_]\w*", a))
    deltas = {**{v: 0 for v in guard_vars}, **deltas}   # unassigned = invariant
    consts = sorted({int(x) for a in guard_atoms for x in
                     __import__("re").findall(r"-?\d+", a)})
    bounds = [("var", v) for v in sorted(guard_vars)
              if deltas.get(v, 0) == 0] + \
             [("const", k) for k in consts]
    for counter, d in deltas.items():
        if d not in (1, -1):
            continue        # |step| != 1: no unit template
        for kind, bound in bounds:
            if kind == "var" and bound == counter:
                continue
            if kind == "var" and deltas.get(bound, 0) != 0:
                continue    # bound must be loop-invariant
            btxt = str(bound)
            r = f"{btxt} - {counter} + 1" if d == 1 else f"{counter} - {btxt} + 1"
            try:
                discharged = lb.entails(
                    model, lower_condition(f"{r} >= 1"))
            except Exception:
                discharged = False
            if discharged:
                return r    # R decreases by exactly 1 each iter
    return None


def synthesize_ranking(guard_text: str, deltas: dict, lb=None,
                       templates=("unit", "lex", "mult", "disj")) -> dict:
    """Real ranking synthesis: several template families, every candidate
    discharged by entailment -- an undischarged guess is never returned
    as a ranking.

    templates:
      unit  -- bound - counter + 1 for a +/-1 counter (find_ranking).
      lex   -- (R1, R2) lexicographic: R1 is a discharged unit ranking that
               strictly decreases every iteration; R2 is a secondary measure
               proven >= 0 in-loop.  Sound: if R1 strictly decreases each
               step, (R1, R2) decreases lexicographically regardless of R2.
      mult  -- halving/division counters, deltas={"x": "half"}: discharged
               ONLY when the guard entails x >= 1 (a strict positive lower
               bound -- x = 0 halves to 0 and makes no progress).  Ranking
               is the certified measure log2(x) + 1.
      disj  -- disjunctive guard 'A or B': every disjunct must discharge a
               unit ranking; since deltas are per-iteration, ALL rankings
               decrease together, so max(R_a, R_b) is the discharged ranking.
    """
    lb = lb or DEFAULT_BACKEND
    out = {"ranking": None, "kind": None, "discharged": False,
           "reason": "no template discharged"}
    try:
        guard_atoms = atoms_of(lower_condition(guard_text))
        model = lb.learn(guard_atoms)
    except Exception as e:
        out["reason"] = f"guard outside the linear fragment: {e}"
        return out
    if not model.feasible():
        out["reason"] = "guard infeasible -- the loop never runs"
        return out

    def _entails(cond_text: str) -> bool:
        try:
            return lb.entails(model, lower_condition(cond_text))
        except Exception:
            return False

    if "unit" in templates:
        r = find_ranking(guard_text, deltas, lb=lb)
        if r:
            return {"ranking": r, "kind": "unit", "discharged": True,
                    "reason": None}

    if "mult" in templates:
        for var, d in deltas.items():
            if d != "half":
                continue
            if _entails(f"{var} >= 1"):
                return {"ranking": f"log2({var}) + 1", "kind": "mult",
                        "discharged": True, "reason": None,
                        "note": f"guard entails {var} >= 1; each step "
                                f"{var} = {var} // 2 strictly decreases the "
                                "measure while the loop runs"}
            return {"ranking": None, "kind": "mult", "discharged": False,
                    "reason": f"halving counter {var} has no discharged "
                              "strict positive lower bound (x >= 1); "
                              "x = 0 halves to 0 -- refusing to guess"}
    if "lex" in templates:
        unit_deltas = {v: d for v, d in deltas.items() if d in (1, -1)}
        if len(unit_deltas) >= 2:
            r1 = find_ranking(guard_text, deltas, lb=lb)
            if r1:
                import re as _re
                gvars = sorted({v for a in guard_atoms
                                for v in _re.findall(r"[A-Za-z_]\w*", a)})
                gconsts = sorted({int(x) for a in guard_atoms
                                  for x in _re.findall(r"-?\d+", a)})
                for v2 in sorted(unit_deltas):
                    if v2 in r1:
                        continue                # v2 is already R1's counter
                    bounds = [v for v in gvars
                              if v != v2 and v not in unit_deltas] + \
                             [str(k) for k in gconsts]
                    for bound in bounds:
                        r2 = (f"{bound} - {v2} + 1" if unit_deltas[v2] == 1
                              else f"{v2} - {bound} + 1")
                        if r2 == r1:
                            continue
                        if _entails(f"{r2} >= 0"):
                            return {"ranking": f"({r1}, {r2})",
                                    "kind": "lex", "discharged": True,
                                    "reason": None,
                                    "note": f"primary {r1} strictly decreases "
                                            f"every iteration; secondary {r2} "
                                            ">= 0 in-loop"}
                return {"ranking": None, "kind": "lex", "discharged": False,
                        "reason": "no secondary measure proven >= 0 in-loop"}
        if "lex" in templates and "unit" not in templates:
            return {"ranking": None, "kind": "lex", "discharged": False,
                    "reason": "lexicographic synthesis needs >= 2 unit-delta "
                              "counters"}

    if "disj" in templates:
        parts = re.split(r"\s+or\s+|\s*\|\|\s*", guard_text)
        if len(parts) > 1:
            rs = []
            for p in parts:
                r = find_ranking(p.strip(), deltas, lb=lb)
                if not r:
                    return {"ranking": None, "kind": "disj",
                            "discharged": False,
                            "reason": f"disjunct {p.strip()!r} discharges no "
                                      "ranking -- max() is unsound without "
                                      "every disjunct decreasing"}
                rs.append(r)
            if len(set(rs)) > 1 or rs:
                return {"ranking": f"max({', '.join(sorted(set(rs)))})",
                        "kind": "disj", "discharged": True, "reason": None,
                        "note": "deltas are per-iteration: every component "
                                "decreases together, so max() decreases"}

    return out
