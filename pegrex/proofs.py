"proofs — proof-carrying certificates "

from __future__ import annotations

from fractions import Fraction

from .linsolve import LinearBackend, parse_atom, _normalize


def derive_proof(atoms):
    """Recording Fourier-Motzkin. Returns a certificate
    {"inputs": [atom text], "multipliers": [Fraction]} with every
    multiplier >= 0, or None when the system is feasible (no certificate
    exists -- None is an honest answer, not a failure)."""
    norm = []  # (coeffs, k, mults)
    for i, a in enumerate(atoms):
        txt = str(a).strip()
        if txt in ("(true)", "true"):
            continue
        la = parse_atom(txt)  # raises LinearError if opaque
        for n in _normalize(la):
            norm.append((dict(n.coeffs), n.k,
                         {i: Fraction(1)}))
    ineqs = [(c, k, m) for c, k, m in norm]
    varset = sorted({v for c, _, _ in ineqs for v in c})
    n_in = len(atoms)
    for var in varset:
        highs, lows, others = [], [], []
        for c, k, m in ineqs:
            cf = c.get(var, 0)
            if cf == 0:
                others.append((c, k, m))
            elif cf > 0:   # x + rest <= k  (scaled)
                rest = {v: cc / cf for v, cc in c.items() if v != var}
                highs.append((rest, k / cf, m))
            else:          # -x + rest <= k (scaled)
                rest = {v: cc / -cf for v, cc in c.items() if v != var}
                lows.append((rest, k / -cf, m))
        new = list(others)
        for rh, kh, mh in highs:
            for rl, kl, ml in lows:
                rest = dict(rh)
                for v, cc in rl.items():
                    rest[v] = rest.get(v, Fraction(0)) + cc
                mults = dict(mh)
                for idx, w in ml.items():
                    mults[idx] = mults.get(idx, Fraction(0)) + w
                new.append(({v: cc for v, cc in rest.items() if cc},
                            kh + kl, mults))
        for c, k, m in new:
            if not c and k < 0:
                lam = [m.get(i, Fraction(0)) for i in range(n_in)]
                return {"inputs": [str(a) for a in atoms],
                        "multipliers": lam}
        ineqs = new
    return None


def check_proof(atoms, certificate) -> dict:
    """Independent arithmetic re-verification of a certificate.

    Verifies: every multiplier >= 0; sum(lambda_i * coeffs_i) == 0;
    sum(lambda_i * k_i) < 0. Refuses anything else, loudly."""
    lam = certificate["multipliers"]
    if len(lam) != len(atoms):
        return {"ok": False, "reason": "multiplier/atom count mismatch"}
    if any(l < 0 for l in lam):
        return {"ok": False, "reason": "negative multiplier"}
    total_c = {}
    total_k = Fraction(0)
    for l, a in zip(lam, atoms):
        if l == 0:
            continue
        la = parse_atom(str(a).strip())
        for n in _normalize(la):
            for v, cc in n.cd().items():
                total_c[v] = total_c.get(v, Fraction(0)) + l * cc
            total_k += l * n.k
    if any(v != 0 for v in total_c.values()):
        return {"ok": False, "reason": "variables do not cancel",
                "residual": {v: str(c) for v, c in total_c.items() if c}}
    if not (total_k < 0):
        return {"ok": False, "reason": f"no contradiction (sum k = {total_k})"}
    return {"ok": True, "sum_k": str(total_k)}


def certified_infeasible(atoms, lb=None) -> dict:
    """One call: verdict + certificate + checked proof, or an honest None."""
    lb = lb or LinearBackend()
    model = lb.learn(list(atoms))
    if model.feasible():
        return {"infeasible": False, "certificate": None, "checked": None}
    cert = derive_proof(list(atoms))
    if cert is None:
        # verdict says infeasible but no certificate derived: loud refusal
        return {"infeasible": True, "certificate": None, "checked":
                {"ok": False, "reason": "verdict without certificate"}}
    return {"infeasible": True, "certificate": cert,
            "checked": check_proof(list(atoms), cert)}
