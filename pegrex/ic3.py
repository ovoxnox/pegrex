"""
ic3 - IC3/PDR-lite for linear transition systems.

Honest v1 scope: initiation (I |= P; I |= ~P refutes with a witness),
per-step consecution discharged by the engine, CTI blocking by SOUND
exclusion only, and IC3 generalization (relaxing a blocking frame atom
when init stays covered and the rest stays inductive). Relative induction
toward P' closes a frame chain. Budget exhaustion and opacity are
unknown -- never 'safe' by default."""

from __future__ import annotations

import re

from .ir import lower_condition
from .linsolve import LinearBackend, atoms_of, parse_atom
from .refine import _neg, _norm_constraint
from .sym import And

DEFAULT_LB = LinearBackend()
_IDENT = re.compile(r"[A-Za-z_]\w*")


def _prime(atoms):
    return [_IDENT.sub(lambda m: m.group(0) + "_p", a) for a in atoms]


def _unprime(atoms):
    return [a.replace("_p", "") for a in atoms]


def _goal(atoms):
    ls = [lower_condition(a) for a in atoms]
    return And(*ls) if len(ls) > 1 else ls[0]


def _norm(atoms, lb):
    out = []
    for a in atoms:
        n = _norm_condition(str(a))
        try:
            parse_atom(n)
            out.append(n)
        except Exception:
            return None
    return out


def _norm_condition(text):
    return _norm_constraint(text)


def prove(init_atoms, trans_primed_texts, prop_text, lb=None, max_frames=6):
    lb = lb or DEFAULT_LB
    init_norm = _norm(init_atoms, lb)
    if init_norm is None:
        return {"status": "unknown", "reason": "init outside the fragment"}
    m0 = lb.learn(init_norm)
    try:
        prop_atoms = atoms_of(lower_condition(prop_text))
    except Exception:
        return {"status": "unknown", "reason": "property outside the fragment"}
    if lb.entails(m0, _neg(lower_condition(prop_text))):
        return {"status": "refuted", "reason": "init already violates P",
                "witness": m0.model()}
    try:
        trans_raw = atoms_of(lower_condition(" and ".join(trans_primed_texts)))
    except Exception:
        return {"status": "unknown", "reason": "transition outside fragment"}
    trans_norm = _norm(trans_raw, lb)
    if trans_norm is None:
        return {"status": "unknown", "reason": "opaque transition"}

    # PDR stutter: frame variables untouched by the transition keep
    # their value (v_p - v = 0); otherwise consecution on unchanged vars
    # is unsatisfiable -- the classic encoding, made explicit
    trans_vars = set()
    for a in trans_norm:
        for v in _IDENT.findall(a):
            trans_vars.add(v.replace("_p", ""))
    for a in list(init_norm):
        for v in _IDENT.findall(a):
            base = v.replace("_p", "")
            if base not in trans_vars and not v.endswith("_p"):
                extra = atoms_of(lower_condition(base + "_p - " + base + " = 0"))
                en = _norm(extra, lb)
                if en is None:
                    return {"status": "unknown",
                            "reason": "stutter encoding outside fragment"}
                trans_norm = trans_norm + en
                trans_vars.add(base)

    frontier = set(init_norm)
    for step in range(1, max_frames + 1):
        m = lb.learn(sorted(frontier) + trans_norm)
        if not m.feasible():
            return {"status": "unknown",
                    "reason": "transition infeasible at step %d" % step}
        failed = False
        for a in sorted(frontier):
            primed = _prime(atoms_of(lower_condition(a)))
            if not primed:
                continue
            if lb.entails(m, _goal(primed)):
                continue
            neg = _norm(_unprime(atoms_of(_neg(lower_condition(primed[0])))), lb)
            added = False
            if neg is not None:
                for na in neg:
                    trial = lb.learn(sorted(frontier | set([na])))
                    if trial.feasible():
                        frontier = frontier | set([na])
                        added = True
            if added:
                continue
            relaxed = frontier - set([a])
            if not relaxed:
                failed = True
                break
            neg_relaxed = []
            for x in sorted(relaxed):
                xs = atoms_of(lower_condition(x))
                if xs:
                    neg_relaxed += atoms_of(_neg(lower_condition(xs[0])))
            nr = _norm(neg_relaxed, lb)
            if nr is None:
                failed = True
                break
            cov = lb.learn(init_norm + nr)
            if cov.feasible():
                failed = True
                break
            mr = lb.learn(sorted(relaxed) + trans_norm)
            ok = mr.feasible()
            for x in sorted(relaxed):
                if not ok:
                    break
                ok = lb.entails(mr, _goal(_prime(atoms_of(lower_condition(x)))))
            if ok:
                frontier = relaxed
            else:
                failed = True
                break
        if failed:
            return {"status": "unknown",
                    "reason": "CTI at step %d admits no sound move" % step}
        m2 = lb.learn(sorted(frontier) + trans_norm)
        if lb.entails(m2, _goal(_prime(prop_atoms))):
            return {"status": "proved", "frames": step,
                    "frame_size": len(frontier)}
    return {"status": "unknown",
            "reason": "frame budget %d spent" % max_frames}
