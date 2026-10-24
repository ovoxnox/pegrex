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
