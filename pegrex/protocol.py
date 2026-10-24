"""protocol.py -- smart-contract protocol verification: compose contract
calls, then check a protocol invariant (e.g. conservation of value) across
the composed paths."""
from __future__ import annotations

from .summaries import compose, expand_calls
from .smt import learn, entails


def verify_protocol(caller_contract, contracts, params, invariant) -> dict:
    """Whole-protocol contract = transitive expansion; the invariant must be
    entailed by every feasible path's constraints."""
    full = expand_calls(caller_contract, contracts, params)
    bad = None
    for cons, _res in full:
        if not learn(cons).feasible():
            continue
        if not entails(learn(cons), invariant):
            bad = cons
            break
    return {"holds": bad is None, "paths": len(full), "counterexample": bad}
