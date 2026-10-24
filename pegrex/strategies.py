"""
strategies — property-based test generation 

║  Path constraints -> Hypothesis strategies. Ranges come from sampled 
║  engine models (never invented); a validator re-checks every sampled 
║  input against the path atoms -- a strategy that can emit a violating 
║  input is a bug, caught loudly. """

from __future__ import annotations

from .linsolve import LinearBackend, parse_atom

DEFAULT_LB = LinearBackend()


def sample_models(atoms, n=8, lb=None):
    """Distinct concrete models for an atom list (fewer if the region is
    small -- never more than actually exist)."""
    lb = lb or DEFAULT_LB
    m = lb.learn(atoms)
    if not m.feasible():
        return []
    seen, out = set(), []
    for _ in range(n * 6):
        vals = m.model()
        if not vals:
            break
        key = tuple(sorted(vals.items()))
        if key not in seen:
            seen.add(key)
            out.append(vals)
        if len(out) >= n:
            break
        # exclude the whole point (all vars) to force a different model
        excl = [f"(1*{v} != {val})" for v, val in vals.items()]
        m2 = lb.learn(list(atoms) + excl)
        if not m2.feasible() or not m2.model():
            break
        m = m2
    return out


def strategy(atoms, lb=None) -> dict:
    """{var: [lo, hi]} integer ranges over sampled models."""
    models = sample_models(atoms, lb=lb)
    if not models:
        return {"one_of": []}
    vars_ = sorted({v for mdl in models for v in mdl})
    return {"integers": {v: [min(m[v] for m in models),
                             max(m[v] for m in models)] for v in vars_}}


def emit_hypothesis(strat: dict, fn_name: str = "target") -> str:
    """Hypothesis source for a strategy dict."""
    ints = strat.get("integers", {})
    if not ints:
        return f"# no feasible inputs for {fn_name}"
    args = ", ".join(f"{v}=st.integers({lo}, {hi})" for v, (lo, hi) in ints.items())
    return (f"@given({args})\n"
            f"def test_{fn_name}_path({', '.join(ints)}):\n"
            f"    assert {fn_name}({', '.join(ints)}) is not None")


def validate(atoms, samples, lb=None) -> list:
    """Samples that violate any (linear) atom -- must be []."""
    lb = lb or DEFAULT_LB
    bad = []
    for s in samples:
        for a in atoms:
            try:
                la = parse_atom(str(a))
            except Exception:
                continue
            body = sum(c * s.get(v, 0) for v, c in la.cd().items())
            if la.op == "<=": ok = body <= la.k
            elif la.op == ">=": ok = body >= la.k
            elif la.op == "=": ok = body == la.k
            elif la.op == "!=": ok = body != la.k
            if not ok:
                bad.append({"sample": s, "atom": str(a)})
                break
    return bad
