---
name: pegrex-specs
description: Generate AI-consumable spec schemas (multi-view analysis with prioritized, machine-checkable tasks). Use when starting a refactor, onboarding to a codebase, or preparing agent task lists.
---

# pegrex spec generation

## Command
    python pegrex.py spec <source.py> <name> [--out specs]
    python pegrex.py spec <dir> <name> --dir          # recursive batch

## What you get
`<out>/<name>.spec.json`:
- `tasks[]` — prioritized (P0–P4), each with `acceptance_criteria` and
  MACHINE-CHECKABLE `verify` commands — these are your TDD loop steps
- `analysis.finding_counts` — per-analyzer, per-severity histograms
- `analysis.arch_index` — containers/modules/owns for navigation
- `analysis.opus` — per-perspective summaries (security/refactor/testing/
  documentation/architecture)
- `contract_check` — manifest self-validation (should be [])

## Conventions
- Tasks are sorted by priority; execute P0/P1 first.
- `verify` commands are the loop exit criteria: run them after each task.
- Specs are deterministic (sorted keys) — diff two runs to see drift.

