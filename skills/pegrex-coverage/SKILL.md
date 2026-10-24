---
name: pegrex-coverage
description: Turn coverage data into constraint-aware gap analysis and synthesized tests. Use when test coverage is low or when asked which inputs to test.
---

# coverage gaps and test synthesis

## Producing LCOV
- Python:  coverage run -m pytest && coverage lcov -o cov.lcov
- Go:      go test -coverprofile=c.out && gcov2lcov -infile c.out -o cov.lcov
- Rust:    cargo llvm-cov --lcov --output-path cov.lcov
- JS/TS:   nyc --reporter=lcov npm test

## Commands
    python pegrex.py coverage <src> --lcov cov.lcov [--dir]
    python pegrex.py gaps <src> --lcov cov.lcov
    python pegrex.py tests <src> --lcov cov.lcov   # synthesized pytest tests

## Reading gaps
Each gap is a SATISFIABLE but uncovered path WITH its constraint context:
    gap: ['(not (n = 0))']  ->  write a test with n != 0
`python pegrex.py tests` emits those tests with concrete inputs already
filled in (SMT model extraction).

## Gotchas
- Huge path counts (1000+) come from sequential ifs — normal, capped output.
- Guards the engine can't model (`while True:`, truthiness) appear as
  opaque `cond_*` symbols; the analysis continues around them.
- Whole-module files (no top-level def) are analyzed as modules — correct.

