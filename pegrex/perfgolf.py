"""
perfgolf — e-graph performance oracle 

║  Given several expressions believed semantically equivalent (e.g. two  
║  verify_patch-proven-equal implementations' return expressions), build  
║  one e-graph over all of them and saturate with oracle-validated sound  
║  arithmetic identities (eggx's refusal-oracle discipline: a rule runs   
║  only if a sample check agrees first). If the available sound rules    
║  cannot independently connect every expression into one equivalence    
║  class, this refuses to rank them -- trusting a caller's equivalence    
║  claim is not the same as proving it, and ranking un-connected          
║  expressions as if interchangeable would be a silent unsoundness.      
║  Once connected, every member of the shared class is ranked by op-     
║  count (recursive subtree cost, not a flat per-node guess), and the    
║  cheapest is suggested as the refactor target."""

from __future__ import annotations

import ast

from .eggx import saturate_vars, validate_rule
from .egraphs import EGraph

_BINOPS = {ast.Add: "add", ast.Sub: "sub", ast.Mult: "mul"}
_SYMS = {"add": "+", "sub": "-", "mul": "*"}

_PAIR_SAMPLES = [(a, b) for a in range(-3, 4) for b in range(-3, 4)]

# oracle-validated identities (eggx node-var patterns: '?x' binds
# any node, not just a literal). Each is checked against integer samples
# before being trusted -- see rules below. Commutativity entries use
# 2-variable samples (pairs) since they need two free variables.
_IDENTITIES = [
    (("add", "?x", 0), "?x", lambda x: x + 0, lambda x: x, "x+0=x",
     range(-4, 5)),
    (("add", 0, "?x"), "?x", lambda x: 0 + x, lambda x: x, "0+x=x",
     range(-4, 5)),
    (("mul", "?x", 1), "?x", lambda x: x * 1, lambda x: x, "x*1=x",
     range(-4, 5)),
    (("mul", 1, "?x"), "?x", lambda x: 1 * x, lambda x: x, "1*x=x",
     range(-4, 5)),
    (("mul", "?x", 0), 0, lambda x: x * 0, lambda x: 0, "x*0=0",
     range(-4, 5)),
    (("mul", 0, "?x"), 0, lambda x: 0 * x, lambda x: 0, "0*x=0",
     range(-4, 5)),
    (("sub", "?x", "?x"), 0, lambda x: x - x, lambda x: 0, "x-x=0",
     range(-4, 5)),
    (("add", "?x", "?x"), ("mul", 2, "?x"), lambda x: x + x, lambda x: 2 * x,
     "x+x=2*x", range(-4, 5)),
    (("mul", 2, "?x"), ("add", "?x", "?x"), lambda x: 2 * x, lambda x: x + x,
     "2*x=x+x", range(-4, 5)),
    (("add", "?x", "?y"), ("add", "?y", "?x"),
     lambda p: p[0] + p[1], lambda p: p[1] + p[0], "x+y=y+x", _PAIR_SAMPLES),
    (("mul", "?x", "?y"), ("mul", "?y", "?x"),
     lambda p: p[0] * p[1], lambda p: p[1] * p[0], "x*y=y*x", _PAIR_SAMPLES),
]


def _build_sound_rules():
    """Validate every identity above against integer (or integer-pair)
    samples before admitting it -- the same never-assume-soundness
    discipline eggx uses elsewhere. A rule that failed its own oracle
    would be a bug in THIS module's identity list, not something to paper
    over: it is still refused, not fixed up silently."""
    rules = []
    for lhs, rhs, lfn, rfn, name, samples in _IDENTITIES:
        verdict = validate_rule(lfn, rfn, samples=samples, name=name)
        rules.append(((lhs, rhs), verdict))
    return rules


SOUND_RULES = _build_sound_rules()


def compile_expr(g: EGraph, expr: str, var_nodes: dict) -> int:
    """Parse a simple arithmetic expression (names, ints, + - *) into
    e-graph nodes. Each distinct variable NAME reuses one shared node
    (var_nodes), so multiple expressions compiled into the same graph can
    actually be compared/unified -- without that, "x" in expr A and "x"
    in expr B would just be two unrelated leaves that happen to render
    the same."""
    from .ir import parse_expr, to_sym
    from .sym import Op as _Op, Sym as _Sym
    _SYM_OPS = {"+": "add", "-": "sub", "*": "mul"}
    tree = to_sym(parse_expr(expr))

    def build(node):
        """build(node): see module docstring."""
        if isinstance(node, _Op) and node.op in _SYM_OPS and len(node.args) == 2:
            return g.add(_SYM_OPS[node.op],
                         (build(node.args[0]), build(node.args[1])))
        if isinstance(node, _Sym):
            if node.name not in var_nodes:
                var_nodes[node.name] = g.add("var", (), node.name)
            return var_nodes[node.name]
        if isinstance(node, int) and not isinstance(node, bool):
            return g.add("lit", (), node)
        raise ValueError("perfgolf: unsupported expression syntax (only "
                         "names, int literals, + - * are in the fragment)")
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.USub) \
                and isinstance(node.operand, ast.Constant):
            return g.add("lit", (), -node.operand.value)
        raise ValueError(f"perfgolf: unsupported expression syntax "
                          f"{ast.dump(node)!r} (only names, int literals, "
                          f"+ - * are in the supported fragment)")

    return build(tree)


def _cost_and_text(g: EGraph, root: int, memo: dict, visiting=frozenset()):
    """(op-count, rendered-text) for the cheapest member of root's
    equivalence class. Recursive subtree cost (unlike EGraph.extract's
    default flat per-node cost): a node is only as cheap as its cheapest
    possible children, chosen independently per sub-equivalence-class.

    Saturated e-graphs can have cycles in the "class A's cheapest choice
    needs class B's cost, which needs class A's" dependency sense (a known
    e-graph extraction hazard, not unique to this code) -- `visiting`
    tracks classes currently being resolved up the call stack; a
    candidate that recurses back into one of them is excluded (treated as
    unusable at this level) instead of infinitely recursing."""
    r = g.find(root)
    if r in memo:
        return memo[r]
    if r in visiting:
        return (float("inf"), None)
    visiting = visiting | {r}
    best = None
    for j, n in enumerate(g.nodes):
        if g.find(j) != r:
            continue
        if n.op == "lit":
            cand = (0, str(n.value))
        elif n.op == "var":
            cand = (0, n.value)
        else:
            subs = [_cost_and_text(g, a, memo, visiting) for a in n.args]
            if any(c == float("inf") for c, _ in subs):
                continue  # this definition is cyclic here
            cost = 1 + sum(c for c, _ in subs)
            cand = (cost, f"({subs[0][1]} {_SYMS[n.op]} {subs[1][1]})")
        if best is None or cand[0] < best[0]:
            best = cand
    memo[r] = best if best is not None else (float("inf"), None)
    return memo[r]


def op_count(g: EGraph, root: int) -> int:
    """Op-count of the cheapest member of root's equivalence class."""
    return _cost_and_text(g, root, {})[0]


def _literal_cost(g: EGraph, node_id: int) -> int:
    """Cost of the expression as literally written -- walks the node's own
    children directly (node ids/args are stable forever; union-find only
    affects which class a node belongs to, never the node itself). This is
    deliberately not equivalence-aware: two expressions unioned into the
    same class still get their own distinct as-written costs here, which
    is the whole point of a before/after comparison."""
    n = g.nodes[node_id]
    if n.op in ("lit", "var"):
        return 0
    return 1 + sum(_literal_cost(g, a) for a in n.args)


def rank_equivalent_forms(exprs: list, extra_rules=None) -> dict:
    """Rank several believed-equivalent expressions by op-count.

    Builds one e-graph over all of `exprs`, saturates with rules
    (plus any caller-supplied extra_rules, each independently validated by
    validate_rule before being admitted), then checks every expression
    landed in one shared equivalence class. If not: refused, with the
    reason and which rules were available -- never a silent "assume
    they're equal" ranking. If connected: every input is ranked by its own
    as-written op-count (not the class's cheapest -- that would make every
    member look identically "cheap" and defeat the point of ranking them),
    and the cheapest member the e-graph can construct for that whole class
    (which may differ textually from every input -- the e-graph explores
    the full rewrite-reachable family, not just what was literally
    submitted) is named separately as the suggested refactor target."""
    g = EGraph()
    var_nodes = {}
    roots = [compile_expr(g, e, var_nodes) for e in exprs]
    rules_with_oracles = SOUND_RULES + list(extra_rules or [])
    admitted_report = saturate_vars(g, rules_with_oracles)
    classes = {g.find(r) for r in roots}
    if len(classes) != 1:
        return {"status": "unconnected",
                "reason": "the sound rewrite rules available could not "
                          "independently connect these expressions into "
                          "one equivalence class -- refusing to rank them "
                          "as interchangeable (prove equivalence first, "
                          "e.g. via semantics.verify_patch, or supply the "
                          "missing identity as an extra_rule)",
                "distinct_classes": len(classes),
                "admitted_rules": admitted_report["admitted"],
                "refused_rules": admitted_report["refused"]}
    memo = {}
    ranked = sorted(
        ({"expr": e, "cost": _literal_cost(g, r)}
         for e, r in zip(exprs, roots)),
        key=lambda row: row["cost"])
    cheapest_cost, cheapest_text = _cost_and_text(g, roots[0], memo)
    return {"status": "ranked", "ranked": ranked,
            "cheapest_in_class": cheapest_text,
            "cheapest_cost": cheapest_cost,
            "admitted_rules": admitted_report["admitted"]}
