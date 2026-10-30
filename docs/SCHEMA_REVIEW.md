# Public JSON Schema review status — v1.3.0

The catalog contains 147 registered result schemas; 56 have explicit reviewed contracts and 91 remain provisional (inferred top-level contracts). The schema audit verifies
unique IDs, JSON Schema 2020-12 dialect markers, required/property consistency,
recursive object/array structure, and parity between the runtime catalog and
checked-in JSON files. There are no envelope-only schemas.

## Manually reviewed contracts

The following high-value contracts now have explicit nested field constraints
and are tested against runtime results where practical:

- `security-analysis.v1`, `security-scan.v1`, `security-scan-set.v1`
- `iac-audit.v1`, `security-provenance.v1`, `security-provenance-set.v1`
- `security-effectiveness-benchmark.v1`, `rule-effectiveness.v1`
- `plugin-worker.v1`, `agent-action-plan.v1`, `agent-context.v1`
- `taint-summary.v1`, `language-capabilities.v1`, `analysis-session.v1`
- `repository-memory.v1`, `security-regression-memory.v1`, `resource-bounds.v1`
- `path-contract.v2`, `patch-review.v1`, `security-regression-fixture.v1`
- `a2a-task.v1`, `agent-tools.v1`, `analyzer-worker.v1`, `bounded-model-check.v1`
- `finite-domain-proof.v1`, `path-contract-validation.v1`, `osv-scan.v1`
- `tools-api-envelope.v2`, `tools-api-manifest.v2`, `security-policy-decision.v1`
- `test-promotion.v1`, `lockfile-policy.v1`
- `agent-evidence.v1`, `agent-role-evidence.v1`, `multi-agent-change.v1`

## Remaining schema work

The other 91 schemas remain marked `inferred-top-level`. They include useful
field-level information, but their nested semantics have not all been reviewed
against every runtime branch. They must not be described as fully normative
contracts until their producers, error/unknown branches, and optional fields
have dedicated contract tests. The remediation review promoted only the three
agent contracts with new runtime producer tests; it did not mass-promote the
remaining inference-based schemas.

Run `python tools/audit_public_schemas.py --output docs/SCHEMA_CATALOG_AUDIT.json`
to refresh the structural audit and `python tools/audit_public_schemas.py --check`
to require both catalog integrity and an exact fresh snapshot. The audit is
structural; it is not a proof that every schema covers all possible producer outputs.


## v1.3.0 additions

The eight newly registered v1.2.2/v1.3.0 emitted result IDs now have JSON Schema entries and runtime-catalog parity: `repository-immune.v1`, `regression-network.v1`, `observability-twin.v1`, `policy-build-gate.v1`, `hybrid-priority.v1`, `proof-guided-fuzz.v1`, `compositional-verification.v1`, and `state-profile.v1`. Their schemas are inferred from visible result constructors and are therefore marked provisional pending broader producer-branch tests.
