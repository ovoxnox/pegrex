---
name: pegrex-audit
description: Audit source files for security issues with the pegrex engine (patterns + taint + SCA). Use when reviewing code, before merging, or when asked to find vulnerabilities.
---

# pegrex security audit

## When to use
Reviewing any source file; pre-merge checks; vulnerability discovery.

## Commands
    python pegrex.py audit <file>            # human-readable
    python pegrex.py audit <file> --json     # machine-readable
    python pegrex.py rules                   # catalog stats

Supported: .py .js .ts .tsx .go .rs .c .h .cpp .sol .jl .kt .zig .vy

## Reading the output
Findings sorted by severity (CRITICAL first). Each line:
    SEVERITY  CONFIDENCE  RULE-ID  LINE  EVIDENCE
- `confidence: high` = qualified call-name match (precise)
- `confidence: medium` = auto-converted regex (can false-positive; eyeball it)
- `kind: taint` = data-flow finding (source reached a sink)

## Fixing
Every finding carries a `fix` field. CRITICALs first. Re-run `audit` after
each fix batch; the loop ends when only agreed LOWs remain.

## Gotchas (learned in production)
- Text-regex rules (`kind: pattern`) can match innocuous spans on short
  files — cross-check `evidence` before reporting.
- Taint `strict_missing` rules report UNKNOWN for unresolvable identifiers;
  that is intentional (unknown ≠ clean), not a false positive.

