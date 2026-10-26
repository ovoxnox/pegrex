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

## Contract-preserving modernization and API round trips
- `modernize_preserving_contracts` ports COBOL/Fortran to Python/Rust/Go and
  independently reanalyzes the target. Require separate contract, numeric/overflow,
  and data-layout evidence; never promote missing declarations to PROVED.
- Plain Rust overflow remains build-profile UNKNOWN. Go wrap and Python unbounded
  arithmetic are PROVED only within their declared numeric scopes. A source record
  layout does not prove compatible target lowering.
- `check_round_trip` separates generated-stub/static OpenAPI agreement from old/new
  runtime observations. Require a case for every operation; static agreement alone
  is UNKNOWN and a confirmed result mismatch is REFUTED.
- Use `semantic_checksum` to compare normalized contracts, type/domain assumptions,
  and effects without surface syntax. Require confirmed semantic evidence before
  describing a checksum mismatch as a behavioral change.

