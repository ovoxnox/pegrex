"""
eggx — egg-style upgrades over the e-graph

║  (1) rebuild: congruence closure -- parents of merged children merge;
║  (2) analyses: constant-folding values per class;
║  (3) rule validation: a rewrite is admitted only if a semantic oracle 
║      agrees on samples -- unsound rules are refused loudly, never 
║      saturate the graph. This is the refusal-oracle discipline.
║  Note: the base engine's int-patterns bind literals only; general var
║  patterns are future work (documented, not faked)."""

from __future__ import annotations

from .egraphs import EGraph

_EVAL = {
    "add": lambda a, b: a + b,
    "sub": lambda a, b: a - b,
    "mul": lambda a, b: a * b,
}


def congruence_close(g: EGraph) -> int:
    """Rebuild: merge nodes with equal (op, canonical-args). Returns #merges."""
    merges = 0
    changed = True
    while changed:
        changed = False
        seen = {}
        for i, n in enumerate(g.nodes):
            key = ("lit", n.value) if n.op == "lit" \
                  else (n.op, tuple(g.find(a) for a in n.args))
            j = seen.get(key)
            if j is None:
                seen[key] = i
            elif g.find(i) != g.find(j):
                g.union(i, j)
                merges += 1
                changed = True
    return merges


def const_analysis(g: EGraph) -> dict:
    """root -> folded value, for fully-constant classes."""
    vals = {}
    changed = True
    while changed:
        changed = False
        for i, n in enumerate(g.nodes):
            r = g.find(i)
            if r in vals:
                continue
            if n.op == "lit":
                vals[r] = n.value
                changed = True
            elif n.op in _EVAL and len(n.args) == 2 and \
                    all(g.find(a) in vals for a in n.args):
                try:
                    vals[r] = _EVAL[n.op](*[vals[g.find(a)] for a in n.args])
                    changed = True
                except Exception:
                    pass
    return vals


def validate_rule(lhs_fn, rhs_fn, samples=range(-4, 5), name="rule") -> dict:
    """Semantic oracle over integer samples. Unsound -> refused loudly."""
    bad = [s for s in samples if lhs_fn(s) != rhs_fn(s)]
    return {"rule": name, "sound": not bad,
            "samples": len(list(samples)) if not isinstance(samples, range)
                       else len(samples),
            "counterexamples": list(bad)[:4]}


def _apply_once(g: EGraph, rules, fired: set) -> bool:
    """One bounded rewrite round; each (lhs-root, binding) fires at most once.
    The base engine's saturated() can loop forever on rules that keep
    re-firing (every application builds a fresh rhs node) -- bounded +
    fire-once is the sound replacement."""
    changed = False
    for lhs, rhs in rules:
        for i, n in enumerate(g.nodes):
            if g.find(i) != i:
                continue
            m = g._match(lhs, n)
            if m is None:
                continue
            key = (g.find(i), lhs, tuple(sorted(m.items())))
            if key in fired:
                continue
            fired.add(key)
            r = g._build(rhs, m)
            if g.find(r) != g.find(i):
                g.union(i, r)
                changed = True
    return changed


SOUND = {"sound": True, "rule": "builtin", "counterexamples": []}


def saturate_validated(g: EGraph, rules_with_oracles, max_rounds=32) -> dict:
    """Apply only oracle-approved rules (bounded, fire-once); refused ones
    are reported, never run."""
    refused, admitted = [], []
    for rule, oracle in rules_with_oracles:
        verdict = oracle() if callable(oracle) else oracle
        if verdict["sound"]:
            admitted.append(rule)
        else:
            refused.append(verdict)
    fired = set()
    for _ in range(max_rounds):
        if not _apply_once(g, admitted, fired):
            break
    congruence_close(g)
    return {"admitted": len(admitted), "refused": refused}


# ---------------------------------------------------------------------------
# node-variable patterns ('?x' binds any node, not just literals)
# ---------------------------------------------------------------------------

def _match_node(g, pat, nid, env):
    """Pattern with node vars: '?x' binds any node id; ints still bind
    literals; tuples match (op, children...) structurally."""
    if isinstance(pat, str) and pat.startswith("?"):
        if pat in env:
            return env if env[pat] == nid else None
        env = dict(env)
        env[pat] = nid
        return env
    if isinstance(pat, int):
        n = g.nodes[nid]
        return env if n.op == "lit" and n.value == pat else None
    op, *subs = pat
    n = g.nodes[nid]
    if n.op != op or len(n.args) != len(subs):
        return None
    for sp, child in zip(subs, n.args):
        env = _match_node(g, sp, g.find(child), env)
        if env is None:
            return None
    return env


def _build_node(g, pat, env):
    if isinstance(pat, str) and pat.startswith("?"):
        return env[pat]
    if isinstance(pat, int):
        return g.add("lit", (), pat)
    op, *subs = pat
    return g.add(op, tuple(_build_node(g, sp, env) for sp in subs))


def _apply_vars_once(g, rules, fired) -> bool:
    """Fire-once bounded round for node-var rules: each (lhs-root, binding)
    fires at most once, so even associative rules terminate."""
    changed = False
    for lhs, rhs in rules:
        for i, n in enumerate(g.nodes):
            if g.find(i) != i:
                continue
            env = _match_node(g, lhs, i, {})
            if env is None:
                continue
            key = (g.find(i), str(lhs), tuple(sorted(env.items())))
            if key in fired:
                continue
            fired.add(key)
            r = _build_node(g, rhs, env)
            if g.find(r) != g.find(i):
                g.union(i, r)
                changed = True
    return changed


def saturate_vars(g, rules_with_oracles, max_rounds=32) -> dict:
    """Node-var rewriting with the same oracle discipline:
    only sound rules run; every firing is fire-once bounded."""
    refused, admitted = [], []
    for rule, oracle in rules_with_oracles:
        verdict = oracle() if callable(oracle) else oracle
        (admitted if verdict["sound"] else refused).append(
            rule if verdict["sound"] else verdict)
    fired = set()
    for _ in range(max_rounds):
        if not _apply_vars_once(g, admitted, fired):
            break
    congruence_close(g)
    return {"admitted": len(admitted), "refused": refused}
