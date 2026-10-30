# PegRex v1.2.2 — next-generation evidence protocols

## Repository immune system
`pegrex.immune.audit_repository()` evaluates declared import boundaries and path-specific textual invariants. Findings are stable within a given rule/path/target identity. Parse and read failures produce `unknown` coverage; an empty findings list is only `clean-under-configured-rules`, never a general security guarantee.

## Regression memory network
`pegrex.regressionnetwork` stores reproducible cases by canonical SHA-256 identity. Cases containing likely credentials or machine-local paths are rejected, not automatically redacted. Minification is only accepted when a caller-supplied predicate continues to reproduce the target behavior. Network transport and cross-organization sharing are intentionally outside this local module.

## Runtime observability twin
`pegrex.observability.ingest_trace()` correlates runtime event contract IDs with a supplied static contract index. It fingerprints trace data and explicitly marks unobserved static paths as unresolved. Observations are not proof of behavior outside the observed executions.

## Policy-aware release gate
`pegrex.buildgate.evaluate_release()` denies publication when required evidence is missing, an expected artifact digest changes, or an artifact is not pinned. This is a decision function; callers must place it in the actual publication workflow and protect trusted hash inputs.

## Hybrid symbolic/neural scheduling
`pegrex.hybridpriority.prioritize_paths()` accepts an optional heuristic and changes exploration order only. It never returns a semantic verdict. A sound checker or independent evidence must determine proof outcomes.

## Proof-guided fuzzing
`pegrex.proofguidedfuzz.candidates_from_conditions()` handles a deliberately narrow integer predicate syntax and creates candidate inputs. `confirm_counterexample()` only confirms a mismatch when a caller executes the candidate and supplies an independent oracle. Confirmed cases may be fed to a regression store.

## Compositional verification
`pegrex.composition` binds component contracts to implementation hashes, dependencies and explicit obligation IDs. A composition can be `evidence-complete` only when dependencies exist and all obligations are listed as checked. This bookkeeping protocol is not itself a semantic proof; obligation results must come from a trusted checker.

## Trust limitations
All features are conservative foundations. Textual repository rules are not a complete architecture checker; secret detection is heuristic; the regression network does not upload data; a release gate must be integrated into the release workflow; and compositional records do not prove implementation correctness.
