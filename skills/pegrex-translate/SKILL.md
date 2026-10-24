---
name: pegrex-translate
description: Verify cross-language translations and refactors with certificates. Use when porting code, transpiling, or refactoring with behavior-preservation requirements.
---

# translation verification

## Commands
    python pegrex.py contracts <file> [--lang L]     # what the code promises
    python pegrex.py verify <spec.json>              # certificate or refusal
    python pegrex.py certs                           # full proof suite

## The spec shape (specs/fact.json as template)
    variants: [{language, source}, ...]   # two languages, same function
    postprocess.invariants: [...]         # machine-checked exit conditions

## Interpreting results
- "certificate issued" = contracts identical across variants (path-by-path
  constraints AND results)
- "invariant violated" = the translations DIFFER — the printed contracts
  show exactly which path/result diverges
- specs/fact_negative.json MUST refuse — if it passes, the checker is broken

## Rewrites
`idioms` rules in a spec emit guard-checked rewrites (e.g. if/else -> ternary)
as artifacts; m6 proves the emitted C compiles and runs identically.

