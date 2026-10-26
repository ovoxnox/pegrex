"""Model checking with explicit transition bounds and concrete witnesses."""
from __future__ import annotations

from collections import deque
import json

from .smt import learn, entails


def check_invariant(transitions_atoms, invariant) -> dict:
    """Historical finite-list invariant check (all supplied transitions)."""
    bad = None
    for index, atoms in enumerate(transitions_atoms):
        model = learn(atoms)
        if not entails(model, invariant):
            bad = {"transition": index, "constraints": atoms}
            break
    return {"holds": bad is None, "counterexample": bad}


def bounded_check(initial_states, transitions, invariant, *, max_depth: int,
                  max_states: int = 10_000) -> dict:
    """Breadth-first bounded model checking over a concrete transition system.

    ``transitions(state, depth)`` returns successor states. ``invariant``
    returns True/False, or None when its decision is unknown. ``proved`` is
    reserved for a fully exhausted finite graph; reaching a depth/state cap
    without a violation is UNKNOWN, never a bounded proof of unbounded safety.
    """
    if max_depth < 0 or max_states <= 0:
        raise ValueError("max_depth must be nonnegative and max_states positive")
    queue = deque((state, [state], 0) for state in initial_states)
    seen = set()
    unknowns: list[str] = []
    bound_reached = False
    explored = 0

    def key(state):
        """Implement key with the module's explicit API and failure semantics."""
        return json.dumps(state, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, default=repr)

    while queue:
        state, trace, depth = queue.popleft()
        identity = key(state)
        if identity in seen:
            continue
        if len(seen) >= max_states:
            unknowns.append(f"state cap {max_states} exceeded")
            bound_reached = True
            break
        seen.add(identity)
        explored += 1
        try:
            holds = invariant(state)
        except Exception as exc:
            holds = None
            unknowns.append(f"invariant error at depth {depth}: {type(exc).__name__}: {exc}")
        if holds is False:
            return {
                "schema": "pegrex.bounded-model-check.v1",
                "verdict": "refuted", "holds": False, "complete": True,
                "bound": {"max_depth": max_depth, "max_states": max_states,
                          "reached": depth == max_depth},
                "explored_states": explored,
                "counterexample": {"states": trace, "depth": depth,
                                   "transition_count": depth},
                "unknowns": unknowns,
            }
        if holds is None:
            unknowns.append(f"invariant undecided at depth {depth}")
        if depth >= max_depth:
            bound_reached = True
            continue
        try:
            successors = list(transitions(state, depth))
        except Exception as exc:
            unknowns.append(f"transition error at depth {depth}: {type(exc).__name__}: {exc}")
            continue
        for successor in successors:
            if key(successor) not in seen:
                queue.append((successor, trace + [successor], depth + 1))

    complete = not bound_reached and not unknowns and not queue
    verdict = "proved" if complete else "unknown"
    return {
        "schema": "pegrex.bounded-model-check.v1",
        "verdict": verdict, "holds": True if complete else None,
        "complete": complete,
        "bound": {"max_depth": max_depth, "max_states": max_states,
                  "reached": bound_reached},
        "explored_states": explored,
        "counterexample": None,
        "unknowns": sorted(set(unknowns)) or
                    (["transition bound reached; unbounded safety is not proved"]
                     if bound_reached else []),
    }


def check_invariant_bounded(transitions_atoms, invariant, *, max_depth: int) -> dict:
    """Status-bearing bounded adapter for the historical constraint lists."""
    from .linsolve import LinearBackend
    backend = LinearBackend()
    unknowns: list[str] = []
    for index, atoms in enumerate(transitions_atoms[:max_depth + 1]):
        verdict = backend.entails_with_status(backend.learn(atoms), invariant)
        if verdict["status"] == "not_entailed":
            return {"schema": "pegrex.bounded-model-check.v1",
                    "verdict": "refuted", "holds": False,
                    "bound": {"max_depth": max_depth, "reached": False},
                    "counterexample": {"transition": index, "constraints": atoms},
                    "unknowns": []}
        if verdict["status"] == "unknown":
            unknowns.append(f"transition {index}: {verdict.get('reason', 'undecided')}")
    bounded = len(transitions_atoms) > max_depth + 1
    if bounded:
        unknowns.append(f"only transitions 0..{max_depth} checked")
    complete = not bounded and not unknowns
    return {"schema": "pegrex.bounded-model-check.v1",
            "verdict": "proved" if complete else "unknown",
            "holds": True if complete else None,
            "bound": {"max_depth": max_depth, "reached": bounded},
            "counterexample": None, "unknowns": unknowns}
