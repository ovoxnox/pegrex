"""
autopwn - the composed agent loop: harness gates bounty feeds CEGIS.

One call: (1) the harness checks the agent's plan against the safety
policy before anything runs; (2) the bounty agent discovers the sink
and solves a payload; (3) a CEGIS loop repairs the source under a
PAYLOAD-KILLED verifier (a security fix should change behaviour -- the
gate is "this exact payload no longer reaches the sink", not equivalence;
an UNGUARDED sink is worse, never "fixed"). Refusal at any stage stops
the loop with the reason."""

from __future__ import annotations

import re

from .bounty import run as bounty_run, discover as _disc, solve_payload as _sp
from .cegis import repair as _cegis_repair
from .harness import check_plan, default_policy


def _killed_verifier(sink, payload):
    """Verifier factory: verified == payload can no longer reach sink."""
    def check(a_path, b_path, claim="equivalent"):
        """check(a_path, b_path, claim): see module docstring."""
        src = open(b_path).read()
        has_sink = re.search(rf"{re.escape(sink)}\s*\(", src) is not None
        if not has_sink:
            return {"verified": True, "counterexample": None}
        guard = _disc(src, sink)
        if guard is None:
            # sink present but unguarded: worse, not fixed
            return {"verified": False,
                    "counterexample": {"inputs": payload,
                                       "reason": "sink is now unguarded"}}
        still = _sp(guard)
        if still and all(still.get(k) == v for k, v in payload.items()):
            return {"verified": False,
                    "counterexample": {"inputs": payload}}
        return {"verified": True, "counterexample": None}
    return check


def autopwn(vuln_src, sink, propose_fn, policy=None, max_rounds=4):
    """autopwn(vuln_src, sink, propose_fn, policy, max_rounds): see module docstring."""
    plan = [{"tool": "read", "path": "src/vuln.py"},
            {"tool": "shell", "args": "pytest exploit_test.py"},
            {"tool": "write", "path": "src/vuln_fix.py"}]
    gate = check_plan(plan, policy or default_policy())
    if not gate["safe"]:
        return {"status": "refused", "layer": "policy",
                "reason": gate["verdicts"][-1].get("reason",
                                                   "plan out of policy")}
    discovery = bounty_run(vuln_src, sink)
    if discovery["status"] != "poc":
        return {"status": "unknown", "layer": "discovery",
                "reason": discovery.get("reason", "no payload derivable")}
    rep = _cegis_repair(vuln_src, propose_fn,
                        verifier=_killed_verifier(sink, discovery["payload"]),
                        max_rounds=max_rounds)
    if not rep["verified"]:
        return {"status": "refused", "layer": "fix-ineffective",
                "payload": discovery["payload"], "trail": rep["trail"]}
    return {"status": "poc-fixed", "payload": discovery["payload"],
            "guard": discovery["guard"],
            "minimal_guard_atoms": discovery["minimal_guard_atoms"],
            "patch": rep.get("patch"), "rounds": rep["rounds"]}
