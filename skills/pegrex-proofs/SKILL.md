---
name: pegrex-proofs
description: Advanced proof machinery: IC3 frame pushing, termination ranking synthesis, proof-carrying infeasibility certificates, and evidence packing. Use for deep verification tasks.
---

# proof engines

- `ic3.prove(init_atoms, ["i_p - i = 1"], "i >= 1")`: frames pushed
  with sound-only CTI blocking + generalization; unknown on budget.
- `rank.synthesize_ranking(guard, deltas, templates=("unit","lex",
  "mult","disj"))`: every candidate discharged by entailment.
- `proofs.derive_proof(atoms)`: linear-combination certificates;
  `check_proof` re-verifies arithmetic independently.
- `evidence.pack`/`zkproof.prove`: HMAC-sealed evidence; offline
  toolchain gaps REFUSE rather than substitute weak hashes silently.

## Replayable verification evidence
- `refine_paths` keeps proof records for infeasible and dominated paths.
- `minimize_symbolic_witness` rechecks every model shrink against constraints.
- `export_smtlib` needs no solver; `crosscheck_smtlib` optionally uses Z3.
- `python pegrex/proofreplay.py CERT.json` independently replays canonical equality
  certificates with standard-library JSON/SHA-256 and no solver.
- `check_state_machine`, `analyze_resource_bounds`, and `verify_compiler_change`
  retain three-valued results; caps and unsupported fragments are UNKNOWN.

## External provers and compiler IR
- `export_prover` targets Why3, SMT-LIB, Lean, and Coq without implementing those
  proof systems internally. Exports start `unknown` / `not-checked`; Lean/Coq use
  explicit `sorry`/`Admitted` markers. `check_prover_export` requires external proof
  evidence or a confirmed counterexample.
- `parse_compiler_ir` handles only registered LLVM 17/18, MIR `rust-1`, and MLIR
  `1` grammars. CFG edges must come from parsed terminators, never regex guesses.
  Unsupported terminators, versions, and incomplete graphs remain UNKNOWN.

## Assurance continuity and semantic checksums
- Pin every assurance claim edge to evidence and exact upstream SHA-256 identities.
  Changed upstream content invalidates dependent proofs to UNKNOWN; unchanged content
  keeps its evidence. Never treat stale proof as current.
- `semantic_checksum` diffs normalized contracts, explicit domains/types, and
  location-independent effects across languages. A checksum mismatch is UNKNOWN
  without confirmed semantic evidence, not automatically a behavioral counterexample.
