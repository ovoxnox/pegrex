---
name: pegrex-concolic
description: Run code concretely, collect branch traces, and flip branches by solving path constraints. Use for test generation and coverage-driven exploration.
---

# concolic execution

- `concolic.trace_fn(fn, *args, source=SRC)` -> {"result", "branches":
  [(line, condition, truth)], "opaque_branches": n}.
- `flip_and_verify(fn, run, branch_index, source=SRC)` solves the
  negated branch via Fourier-Motzkin, RE-RUNS, and confirms the flip.
- Opaque predicates are reported, never guessed. Infeasible flips say
  so. Args are bound by signature order, not dict order.
