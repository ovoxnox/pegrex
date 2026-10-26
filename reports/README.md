# PegRex 1.1.0 self-analysis evidence

Generated locally on 2026-10-26 from the exact source snapshot in `PegRex-1.1.0-production.zip`.

Production source archive SHA-256: `8440b91cf991dcfa4559ee6aa27d0696ad461ada7a830dd59bc18ef1d5f285d5`.

## Contents

- `coverage/`: raw coverage data, LCOV, JSON, XML, HTML, text summary, and CoreEngine path-coverage/gap overlays. The final suite measured 19,852 engine statements: 8,019 covered, 11,833 missed, 40% line coverage.
- `rag/`: 1,294 function-aware/windowed chunks, 17,065 inverted-index terms, document lengths, and example hybrid retrieval results. Sources include the engine, tools, tests, and top-level service/pipeline modules.
- `graphs/`: full-engine call twin, DOT call graph, per-file facts, unified graph, semantic dependency graph, and semantic refresh evidence.
- `repository/`: architecture index, bounded incremental index/state, contract-derived repository memory, agent context, semantic digital twin, and core-scoped persistent memory. The expensive persistent contract index is explicitly scoped to the four `pegrex/core` files; three retain UNKNOWN analysis evidence. This is not represented as whole-engine contract proof.
- `specs/`: final HEALTH specification and exact dispositions, soundness manifest, active/disabled rule catalog, CoreEngine operations, and Tools API v2 manifest.
- `security/`: complete structured audit evidence for all 227 engine files, SARIF 2.1.0, and a compact summary. Scanner coverage is complete. Four residual pattern findings correspond to the documented operator-code-execution boundary and generated-stub secret-pattern false positive.
- `supply-chain/`: 19-component CycloneDX 1.5 and SPDX 2.3 SBOMs, offline SCA evidence, and OSV provenance. All 19 pinned dependencies have explicit UNKNOWN results because no authoritative offline OSV snapshot was supplied; this is not a clean vulnerability claim.
- `verification-bundles/`: portable constraints/SMT-LIB bundles for selected core analysis modules and an index recording any UNKNOWN generation results.
- `reports/`: SELF, HEALTH, architecture, public contracts, validation record, and cognitive twin report. HEALTH contains 779 dispositioned analyzer tasks (0 HIGH, 558 MEDIUM, 221 LOW), not confirmed-vulnerability counts.
- `validation/`: final test, certificate, installed-wheel smoke, and distribution-build logs. The final suite passed 781 tests; certificates are ALL GREEN.
- `provenance/`: exact source manifest, environment, release identity, and artifact manifest.
- `tools/`: reproducible artifact collector used for the derived repository/RAG/graph/SBOM evidence.

## Trust and scope

UNKNOWN is preserved for missing evidence, parser/resource limits, unavailable OSV data, and incomplete analysis. Static graphs do not exclude unseen runtime behavior. Runtime coverage is not correctness proof. Generated stubs are not verified implementations. No credentials, external application services, or sensitive files were used. The OSV evidence in this bundle was produced offline.
