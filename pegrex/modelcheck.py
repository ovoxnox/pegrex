"""modelcheck.py -- TLA+-style: invariants checked over the policy-IR state
machine (AgentReport.states/transitions).  A counterexample is a concrete
path violating the invariant."""

from __future__ import annotations

from .smt import learn, entails


def check_invariant(transitions_atoms, invariant) -> dict:
    """transitions_atoms: [path-constraint list per transition].
    Returns {holds, counterexample}.  The invariant must hold on every
    reachable transition."""
    bad = None
    for i, atoms in enumerate(transitions_atoms):
        m = learn(atoms)
        if not entails(m, invariant):
            bad = {"transition": i, "constraints": atoms}
            break
    return {"holds": bad is None, "counterexample": bad}
