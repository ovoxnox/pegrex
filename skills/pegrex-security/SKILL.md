---
name: pegrex-security
description: Autonomous bug discovery and repair: find sinks, solve payloads, minimize, fix under a payload-killed verifier. Use for bug-bounty triage and secure-by-construction loops.
---

# autopwn

- `autopwn.autopwn(vuln_src, sink, proposer)` = policy gate -> bounty
  (discover guard, solve payload, minimize) -> CEGIS repair whose
  verifier is "the exact payload no longer reaches the sink".
- An UNGUARDED sink after a fix is WORSE, never "fixed".
- `zk.audit_circuit(circom_src)` flags under-constrained `<--` and
  outputs absent from all `===` constraints.
