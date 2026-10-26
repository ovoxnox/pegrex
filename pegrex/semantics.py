"""
semantics — semantic diff + patch verification 

║  Behavior as path contracts, not changed lines. semantic_diff compares 
║  the contract sets of two sources; verify_patch issues a proof or a 
║  concrete distinguishing input (a counterexample), never a shrug."""

from __future__ import annotations

from . import api
from .linsolve import LinearBackend, LinAtom, LinearError, parse_atom


def _canon_result(res) -> str:
    "Linear results in normal form; nonlinear stay raw."
    try:
        from .ir import linearize, to_sym, parse_expr
        lin = linearize(to_sym(parse_expr(str(res))))
        if lin is not None:
            return f"lin:{tuple(sorted(lin[0].items()))}|{lin[1]}"
    except Exception:
        pass
    return f"raw:{res}"


def _render_atom(a: LinAtom) -> str:
    "LinAtom -> the same text style cond_to_atom emits."
    terms = []
    for v, c in a.coeffs:
        if not terms:
            terms.append(f"{c}*{v}")
        else:
            terms.append(("+ " if c >= 0 else "- ") + f"{abs(c)}*{v}")
    return "(" + " ".join(terms) + f" {a.op} {a.k})"


def _int_canon(txt: str) -> str:
    """Integer-canonical inequality text: (a < k) and (a <= k-1) are the same
    constraint over the integer domain linsolve itself solves (its integer
    slacks, x < k => x <= k-1).  Comparing the canonical text must use the
    same convention or a sound refactor (x < 0  <->  x <= -1) produces a
    false counterexample -- see m146.  Non-integer coefficients and opaque
    atoms pass through unchanged; = / != are untouched."""
    try:
        a = parse_atom(txt)
    except LinearError:
        return txt
    if a.op not in ("<", ">"):
        return txt
    if a.k.denominator != 1 or any(c.denominator != 1
                                   for _, c in a.coeffs):
        return txt
    a = LinAtom(a.coeffs, "<=" if a.op == "<" else ">=",
                a.k - 1 if a.op == "<" else a.k + 1)
    return _render_atom(a)


def contracts_of(path: str):
    """[(frozenset(constraints), canonical-result)] via the engine frontend.
    Constraints are canonicalized through the IR: 'n > 0' and
    'not (n <= 0)' are the same path -- string-level diffs must not fake
    behavioral differences."""
    from .refine import _norm_constraint
    return [ (frozenset(_int_canon(_norm_constraint(str(c))) for c in cs),
              _canon_result(res))
             for cs, res in api.contracts(path) ]


def semantic_diff(path_a: str, path_b: str) -> dict:
    "Behavioral difference as changed path contracts."
    ca = set(map(tuple, contracts_of(path_a)))
    cb = set(map(tuple, contracts_of(path_b)))
    only_a = sorted(ca - cb)
    only_b = sorted(cb - ca)
    return {
        "identical": not (only_a or only_b),
        "distinguishing": [
            {"only_in": "before", "constraints": sorted(c), "result": r}
            for c, r in only_a
        ] + [
            {"only_in": "after", "constraints": sorted(c), "result": r}
            for c, r in only_b
        ],
    }


def verify_patch(before_path: str, after_path: str, claim: str = "equivalent") -> dict:
    """verify_patch(before, after, claim) -> proof | counterexample.

    claim 'equivalent': identical contracts -> verified. Otherwise a
    distinguishing input is produced from the linear fragment of the
    differing path -- and confirmed: the witness must satisfy the differing
    path and fall outside every same-result path on the other side (an input
    where both sides return the same thing is not a counterexample; see
    m146).  When no confirmed witness exists -- opaque constraints, or the
    fragment -- the verdict is still refuted but the counterexample slot is
    honestly empty."""
    d = semantic_diff(before_path, after_path)
    if d["identical"]:
        return {"verified": True, "claim": claim, "counterexample": None,
                "distinguishing": []}
    sides = {"before": contracts_of(before_path),
             "after": contracts_of(after_path)}
    lb = LinearBackend()
    for entry in d["distinguishing"]:
        other = "after" if entry["only_in"] == "before" else "before"
        same_result = [cs for cs, r in sides[other]
                       if r == entry["result"]]
        atoms, opaque = [], False
        for c in entry["constraints"]:
            try:
                parse_atom(str(c))
                atoms.append(str(c))
            except LinearError:
                opaque = True  # cannot confirm a witness on a
        if opaque:             # path we cannot evaluate
            continue
        cand = _find_witness(lb, atoms, same_result)
        if cand is not None:
            return {"verified": False, "claim": claim,
                    "counterexample": {"inputs": cand,
                                       "path": entry["constraints"],
                                       "result": entry["result"],
                                       "only_in": entry["only_in"],
                                       "confirmed": True},
                    "distinguishing": d["distinguishing"]}
    return {"verified": False, "claim": claim, "counterexample": None,
            "distinguishing": d["distinguishing"],
            "note": "no confirmed distinguishing input "
                    "(opaque constraints or fragment limits)"}


def explain_patch(before_path: str, after_path: str) -> dict:
    """Explain changed path contracts and the reason for each behavioral delta.

    Equivalence is PROVED only for identical canonical contracts. A concrete
    confirmed witness REFUTES equivalence; a syntactic contract difference
    without a witness remains UNKNOWN rather than an asserted behavior break.
    """
    diff = semantic_diff(before_path, after_path)
    verification = verify_patch(before_path, after_path)
    entries = diff["distinguishing"]
    changes = []
    effect_changes = []
    effect_unknowns = []
    try:
        from .effects import infer_effects
        from pathlib import Path
        before_effects = infer_effects(Path(before_path).read_text(encoding="utf-8"))
        after_effects = infer_effects(Path(after_path).read_text(encoding="utf-8"))
        names = set(before_effects["functions"]) | set(after_effects["functions"])
        for name in sorted(names):
            def signature(report):
                """Implement signature with the module's explicit API and failure semantics."""
                return sorted((row["category"], row["action"], row["scope"])
                              for row in report["functions"].get(name, {}).get("effects", []))
            before_signature = signature(before_effects)
            after_signature = signature(after_effects)
            if before_signature != after_signature:
                effect_changes.append({"function": name,
                                       "before": before_signature,
                                       "after": after_signature})
    except (NotImplementedError, SyntaxError, UnicodeError) as exc:
        effect_unknowns.append(f"effect comparison unavailable: {exc}")
    for entry in entries:
        opposite_side = "after" if entry["only_in"] == "before" else "before"
        counterpart = next((other for other in entries
                            if other["only_in"] == opposite_side
                            and other["constraints"] == entry["constraints"]), None)
        if counterpart is not None:
            kind = "return-relation"
            reason = "the same path constraints now produce a different observable result"
        else:
            counterpart = next((other for other in entries
                                if other["only_in"] == opposite_side
                                and other["result"] == entry["result"]), None)
            if counterpart is not None:
                kind = "path-domain"
                reason = "the input domain for an observable result changed"
            else:
                kind = "contract-set"
                reason = "a path/outcome pair was added or removed without a one-to-one canonical match"
        changes.append({**entry, "kind": kind, "reason": reason,
                        "action": "removed" if entry["only_in"] == "before" else "added"})
    changes.extend({"only_in": "effects", "kind": "effects", "action": "changed",
                    "reason": "explicit side-effect signature changed", **change}
                   for change in effect_changes)
    if verification["verified"] and not effect_changes and not effect_unknowns:
        verdict = "proved"
        preserving = True
        summary = "No observable path-contract or explicit-effect change detected; patch equivalence is proved."
    elif effect_changes or verification.get("counterexample"):
        verdict = "refuted"
        preserving = False
        summary = (f"Patch equivalence is refuted by "
                   f"{'explicit effect evidence' if effect_changes else 'a confirmed input'} "
                   f"on {len(changes)} changed contract/effect row(s).")
    else:
        verdict = "unknown"
        preserving = None
        summary = (("Return contracts are unchanged, but explicit-effect comparison is incomplete."
                    if diff["identical"] and effect_unknowns else
                    f"Canonical contracts differ on {len(changes)} row(s), but no "
                    "confirmed distinguishing input was found."))
    return {
        "schema": "pegrex.patch-explanation.v1",
        "verdict": verdict,
        "behavior_preserving": preserving,
        "summary": summary,
        "changes": changes,
        "counterexample": verification.get("counterexample"),
        "unknowns": effect_unknowns + ([] if verdict != "unknown" else [
            verification.get("note", "patch equivalence could not be decided")]),
    }


def _eval_atom(txt, vals):
    """atom text @ valuation -> True/False; None when unevaluable (opaque)."""
    try:
        a = parse_atom(str(txt))
    except LinearError:
        return None
    body = sum(c * vals.get(v, 0) for v, c in a.coeffs)
    return {"<": body < a.k, "<=": body <= a.k, ">": body > a.k,
            ">=": body >= a.k, "=": body == a.k,
            "!=": body != a.k}[a.op]


def _covered(vals, same_result_paths):
    """Is `vals` provably inside some same-result path (results agree)?
    Returns True (covered), False (provably outside all), None (opaque
    constraint makes coverage indeterminate -- refuse to guess)."""
    indeterminate = False
    for cs in same_result_paths:
        verdicts = [_eval_atom(c, vals) for c in cs]
        if all(v is True for v in verdicts):
            return True
        if any(v is None for v in verdicts) and not any(v is False
                                                        for v in verdicts):
            indeterminate = True
    return None if indeterminate else False


def _find_witness(lb, atoms, same_result_paths, max_tries=32):
    """An input on the differing path that is provably not covered by any
    same-result path on the other side; None if none found (or unconfirmable)."""
    atoms = list(atoms)
    for _ in range(max_tries):
        model = lb.learn(atoms)
        if not model.feasible():
            return None
        vals = model.model()
        if not vals:
            return None
        cov = _covered(vals, same_result_paths)
        if cov is False:
            return vals
        if cov is None:
            return None                         # opaque: refuse to guess
        var, val = next(iter(vals.items()))     # covered: exclude this point
        atoms.append(f"(1*{var} != {val})")
    return None
