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

## Contract-derived repository planning
- `RepositoryMemory` persists stable API, invariant, dependency, architecture,
  and limitation summaries with content-defined identities.
- `SemanticDependencyGraph` maps modules, functions, contracts, and invariants;
  use `dependencies()` and `impact()` for forward and reverse traversal.
- `plan_changes` ranks candidates by benefit, reachable impact, uncertainty, and
  proof effort. Invalid or missing inputs remain unranked UNKNOWN rows; a plan
  never substitutes for verification or proof-gated application.
- `compile_agent_context` compresses repository memory without silently dropping
  UNKNOWN markers. LLM `propose_spec` output remains a conjecture until an
  independent checker supplies proof or a confirmed counterexample; otherwise it
  is UNKNOWN. A2A tasks must carry budget, deadline, evidence, cancellation, and
  partial-result state.

## Formal protocol evidence
- `parse_protocol` strictly handles JSON, URL, CSV, INI, S-expressions, and
  properties/configuration text. Duplicate keys, malformed escapes, inconsistent
  rows, and trailing input remain UNKNOWN rather than permissively repaired.
- A PROVED protocol result covers only documented well-formedness and the supported
  declarative schema subset; it is not an application-security or semantic proof.

## Semantic PR budgets
- `summarize_semantic_change` separately accounts for public contracts, security
  surface, dependencies, complexity, and UNKNOWN regions. Set explicit nonnegative
  limits and retain every exceeded metric.
- A complete change summary is not merge approval. Missing parser/flow/complexity
  evidence stays an UNKNOWN region rather than a zero-change entry.
