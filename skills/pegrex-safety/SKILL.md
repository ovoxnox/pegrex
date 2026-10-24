---
name: pegrex-safety
description: Constrain coding-agent actions with verified policies. Use to refuse out-of-policy plans BEFORE execution (default-deny, deny precedence).
---

# agent safety harness

- `harness.check_plan([{tool, args, path}, ...])` -> safe + per-action
  verdicts. The first refusal stops the plan; nothing after it runs.
- Unknown tools are refused (default-deny). Deny rules beat matching
  allows. Partial verdicts never claim safety.
