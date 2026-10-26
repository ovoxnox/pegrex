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

## Framework packs and executable security contracts
- `analyze_with_frameworks(source, ("web", "database", "shell",
  "deserialization", "templating", "cloud"))` selects versioned source/sink packs.
- Findings include exact rule/AST/source-span evidence, origin-to-sink chains,
  pack identity, and evidence strength. Preserve this provenance in triage.
- `check_security_contract` enforces declared source/sink prohibitions and required
  transformations. Proof is scoped to selected packs and complete fixed points.
- Secret flows include environment/configuration sources and HTTP payloads.

## Attack paths, reproduction, and regression memory
- Join exposure, identity, asset, dependency, code-flow, and sink evidence with
  `build_attack_graph`. A path cap is UNKNOWN with no partial path list.
- Use the exploitability ladder separately: pattern match, confirmed test,
  symbolic witness, then sandboxed reproduction. A higher label is not exploit
  probability, and missing rungs remain explicit.
- Sandboxed reproduction requires ephemeral isolation and no credentials/network.
  Refuse execution when that boundary is unavailable.
- `register_finding_fix` must generate both a fixed-finding regression and a
  vulnerable-source negative control. Execute both and verify artifact hashes;
  refusal to register is not a clean security result.

## Smart-contract evidence layers
- `analyze_smart_contract` keeps Solidity source heuristics, EVM bytecode checks,
  formal claims, and local-EVM tests independent. Never substitute one for another.
- Bytecode checks must skip PUSH immediate data. Formal PROVED needs proof evidence;
  local tests need confirmed local execution. Missing runners or evidence are
  UNKNOWN, and source-pattern absence is not a proof of safety.

## Reproducible research capsules
- Package the finding, minimized vulnerable source, preconditions, fixed patch,
  regression/negative control, sandbox recipe, and proof/witness together.
- Capsule recipes are argv-only, no-network, and no-credentials. Inclusion is not
  execution. Verify content hashes and the vulnerable-source negative control;
  unconfirmed minimization or witness evidence remains UNKNOWN.
