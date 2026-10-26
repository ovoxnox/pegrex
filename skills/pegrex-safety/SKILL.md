---
name: pegrex-safety
description: Constrain coding-agent actions with verified policies. Use to refuse out-of-policy plans BEFORE execution (default-deny, deny precedence).
---

# agent safety harness

- `harness.check_plan([{tool, args, path}, ...])` -> safe + per-action
  verdicts. The first refusal stops the plan; nothing after it runs.
- Unknown tools are refused (default-deny). Deny rules beat matching
  allows. Partial verdicts never claim safety.

## Fail-closed analysis policy
- `SecurityProfile()` denies UNKNOWN evidence by default. Select failures by
  reason, category, or rule ID and record explicit reason allowances with
  `allow_unknown_reasons`; allowances remain visible rather than becoming clean.
- Proof-gated edits retain rejected attempts. Missing proof, inconclusive
  invariants, test failure/timeout, candidate recheck failure, or disallowed
  UNKNOWN evidence prevents target replacement.
- `run_harness_policy_suite` checks a canonical safe action and mutation-based
  bypasses. Syntax/launcher confinement must survive allow-all policy mutations;
  policy-only denials must be killed. Preserve decision-provenance hash chains.
- `run_poc` is only for declared argv/files inside bubblewrap/prlimit isolation
  with no credentials or network. Missing binaries or namespace setup failure is
  UNKNOWN; never fall back to process limits alone or execute raw shell text.
- The action broker requires exact-plan authorization issued by the policy engine.
  Reject substituted, forged, stale, or revoked capabilities. Preserve actual action
  evidence and mark unobserved filesystem/network effects UNKNOWN.
