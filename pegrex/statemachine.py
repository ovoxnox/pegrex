"""Declarative protocol/state-machine model checking with concrete traces."""
from __future__ import annotations
from collections import deque
import json
SCHEMA = "pegrex.protocol-model-check.v1"


def _match(state, condition): return all(state.get(k) == v for k, v in condition.items())
def _invariant(state, rule):
    value = rule.get("variable")
    if value not in state: return None
    actual, expected, op = state[value], rule.get("value"), rule.get("operator", "==")
    try:
        if op == "==": return actual == expected
        if op == "!=": return actual != expected
        if op == ">=": return actual >= expected
        if op == "<=": return actual <= expected
        if op == ">": return actual > expected
        if op == "<": return actual < expected
        if op == "in": return actual in expected
        if op == "not-in": return actual not in expected
        return None
    except TypeError: return None


def check_state_machine(initial_states, transitions, invariants, *, max_depth=100, max_states=10_000) -> dict:
    """Transitions: {id, when: {var: value}, set: {var: value}}.

    Invariants use variable/operator/value records. A fully exhausted finite
    graph is PROVED; a depth/state cap or undecided invariant is UNKNOWN.
    """
    queue = deque((state, [], 0) for state in initial_states)
    seen, unknowns, explored, bounded = set(), [], 0, False
    def key(state):
        """Implement key with explicit API and failure semantics."""
        return json.dumps(state, sort_keys=True, separators=(',', ':'), default=repr)
    while queue:
        state, trace, depth = queue.popleft()
        identity = key(state)
        if identity in seen: continue
        if len(seen) >= max_states:
            bounded = True; unknowns.append("state cap exceeded"); break
        seen.add(identity); explored += 1
        step = {"state": state, "depth": depth}
        for rule in invariants:
            holds = _invariant(state, rule)
            if holds is False:
                return {"schema": SCHEMA, "schema_version": 1, "verdict": "refuted",
                        "complete": True, "explored_states": explored,
                        "counterexample": {"trace": trace + [step], "invariant": rule["id"]},
                        "unknowns": unknowns}
            if holds is None: unknowns.append(f"invariant undecided: {rule.get('id')}")
        if depth >= max_depth:
            bounded = True; continue
        enabled = [row for row in transitions if _match(state, row.get("when", {}))]
        for transition in enabled:
            following = dict(state); following.update(transition.get("set", {}))
            queue.append((following, trace + [step | {"transition": transition.get("id")}], depth + 1))
    complete = not bounded and not unknowns
    if bounded: unknowns.append("bound reached; unbounded safety not proved")
    return {"schema": SCHEMA, "schema_version": 1,
            "verdict": "proved" if complete else "unknown", "complete": complete,
            "explored_states": explored, "counterexample": None,
            "bound": {"max_depth": max_depth, "max_states": max_states, "reached": bounded},
            "unknowns": sorted(set(unknowns))}
