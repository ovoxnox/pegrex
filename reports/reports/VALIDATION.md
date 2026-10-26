# PegRex validation record

Validated on 2026-10-26 with Python 3.12 for PegRex 1.1.0.

## Regression and compatibility

- Complete historical and expanded suite: **781 passed**; one intentional test warning checks duplicate-path rejection in the release verifier.
- Certificate and pipeline gate: `python pegrex.py certs` — **ALL GREEN**.
- Generated self-host evidence: `python tools/selfhost.py --check` passes.
- HEALTH findings, exact task dispositions, and rendered-report freshness: `python tools/health_report.py --check` passes.
- Packaged skills: `python tools/build_skills.py --check` passes; archive SHA-256 is `5b078360d043ddfd4175e927d7cbd7b69fdcf0e46f9a09d863f1a7cbc56b5ad2`.
- Grammar lint: **0 problems across 11 grammars**. Source compilation and whitespace checks pass.
- Default CLI JSON compatibility, legacy public call shapes, argv-only execution, structured CoreEngine/CLI errors, and versioned evidence envelopes remain covered by regression tests.

## Coverage evidence

The complete suite was run under coverage with `pegrex` as the measured source. The generated LCOV, JSON, XML, HTML, and text reports are supplied in the separate self-analysis evidence archive.

- Engine statements: **19,852**.
- Covered statements: **8,019**.
- Missed statements: **11,833**.
- Line coverage: **40%**.

This is runtime test coverage for the selected suite, not a proof of correctness or a replacement for the static test-reference tasks in HEALTH.

## Distribution smoke tests

Clean-staging wheel and source-distribution builds completed after correcting modern license metadata. The wheel contains every engine module, including `peg.py`, `pdr.py`, and `patterns.py`. It was installed into an empty target and exercised outside the source checkout. **10 installed-wheel smoke checks passed**, covering package version/import, CoreEngine dispatch and structured unknown-operation failure, Tools API v2 manifest/invocation/workspace escape rejection, and the `engine`, `tools`, and `soundness` CLI surfaces.

Validation distribution identities (build products are not duplicated in the trimmed source archive):

- `pegrex-1.1.0-py3-none-any.whl`: `a24c23aea59a58cad113ae48741cdc5473018661dca99412323ca20283064a8d`
- `pegrex-1.1.0.tar.gz`: `857fd777886297e5dd491ee5a73b0c70af128cba19cad9d4faebebfef15b9c41`

## Generated repository evidence

- `docs/SELF.md`: engine digest `d6c8be5e4a8f134a`; 223 modules; 27,567 engine LOC; 1,181 functions and 6,799 call edges in the repository twin; 97 modules with extracted contracts and 126 with explicit UNKNOWN extraction.
- `specs/pegrex_health.spec.json`: 227 engine files and **779 analyzer tasks** (0 HIGH, 558 MEDIUM, 221 LOW).
- `specs/pegrex_health.dispositions.json`: every exact task ID is dispositioned. Testing and structural recommendations remain explicit maintenance evidence; intentional process-local state and operator code execution are documented; the generated-stub credential-pattern match is recorded as a false positive. These tasks are not confirmed-vulnerability counts.
- `docs/HEALTH.md` is mechanically rendered from the exact report digest and dispositions.
- `docs/ARCHITECTURE.md`, `docs/PUBLIC_CONTRACTS.md`, README, and packaged skills document the evidence scope and fail-closed limits through item 86.

## Production hardening evidence

Regressions cover versioned MLIR terminator parsing with both conditional successors, deterministic UTF-8 text versus binary I/O, the coverage-test CLI/API distinction, AST-based documentation and mutable-default analysis, real command sinks, disabled-rule provenance, restricted concolic/loop evaluation, LLM endpoint validation, thread-local idiom rendering, and confirmed-only counterexample promotion.

The release builder emits deterministic ZIP timestamps and ordering, excludes caches/build products, writes exact SHA-256 file identities, and verifies CRCs, unique safe paths, required files, exclusions, and manifest hashes.

## Trust boundaries

No credentials, secrets, external application services, or sensitive files were requested or used. Work remained confined to the uploaded archive, audit document, extracted project, local dependencies, clean local build staging, and local validation. Original `/mnt/agents/upload/pegrex.zip` was not modified.

Missing evidence, parser failures, unavailable OSV data, resource exhaustion, incomplete path enumeration, and unsupported fragments remain UNKNOWN. Legacy heuristic taint is not promoted to proof. Dependency `not-observed` is not absence proof. Resource allocation bounds count sites rather than bytes. Worker isolation is process/rlimit isolation, not container or network/filesystem confinement. PoCs require an ephemeral isolated sandbox with no credentials/network by default; setup failure does not execute the payload. Unconfirmed mutants, witnesses, semantic checksum mismatches, or counterexamples are not confirmed behavioral changes.

Unsigned build statements verify available hashes but do not authenticate builders or hermeticity. The minimal replay/kernel path does not execute counterexamples or trust the broad analyzer's success claim. Static compliance/lifecycle evidence is not operational-effectiveness or legal proof. Observed traces do not make unseen paths impossible. Research-capsule verification does not execute the recipe. Impact simulation does not modify the target or authorize a merge. Action evidence hash chains provide local integrity, not signed attestation; unenumerated shell filesystem effects remain UNKNOWN.
