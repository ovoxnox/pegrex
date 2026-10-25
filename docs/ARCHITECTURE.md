# PegRex architecture: stable core and registered frontends

## Dependency direction

PegRex is organized in four layers. Dependencies point inward; the stable core does not import optional parser bindings, solver backends, audit catalogs, or agent runtimes during module import.

1. **Public adapters** — `pegrex.api`, `pipeline.py`, `service.py`, and the CLI preserve historical call shapes and wire formats.
2. **Stable core** — `pegrex.core.models` defines `SourceDocument`, `PathContract`, `OperationResult`, statuses, verdicts, and versioned serialization. `pegrex.core.contracts` owns conservative canonicalization, deduplication, and syntactic subsumption. `pegrex.core.engine` coordinates registered operations and returns typed results.
3. **Canonical frontend plugin registry** — `pegrex.languages` is the single source for canonical names, aliases, file extensions, parser implementations/versions, coordinate conventions, normalizers, error policies, CFG adapters and supported constructs, expression lowering, contract features, security packs, maturity, known unsupported cases, and advertised capabilities.
4. **Feature adapters** — `tree_sitter_bridge`, `python_ast`, the C PEG grammar frontend, `tscontracts`, COBOL/Fortran adapters, `tools.secaudit`, and solver/semantic modules implement the registered work. They are loaded lazily when a requested operation needs them.

## Language registration

Register a language in `pegrex.languages._SPECS`; do not add an independent language/extension/parser map elsewhere. A `LanguageSpec` separates these questions:

- `extensions` / `aliases`: what input names resolve to the language;
- `capabilities`: which operations are advertised;
- `parser`, `parser_version`, `parse_adapter`, `binding`, `parser_language`: how full-source parsing is obtained;
- `source_coordinates`, `normalizer`, `error_policy`: how syntax trees become safe public spans and how failures surface;
- `cfg_adapter`, `supported_constructs`, `expression_lowering`: the exact analysis fragment;
- `contract_mode`, `contract_features`, `contract_handler`, `frontend_factory`: how contract pairs are extracted;
- `security_rule_packs`, `rule_inherits`: typed rule-pack selection and explicitly compatible inheritance;
- `maturity`, `known_unsupported`: limits that consumers must show rather than hide;
- `comment_prefix`, `tag_spec`, `function_tag`: syntax conventions used by downstream analysis.

A capability is an explicit opt-in. Parser existence does not imply contract extraction, proof, call-graph, or taint support. Unsupported operations raise a capability error/refusal rather than silently falling back to another language. `validate_registry()` checks alias, suffix, dispatch, manifest completeness, and rule-pack consistency. `plugin_registry()` exposes the full manifest; `soundness_report()` adds the trust policy and is available through the core, CLI, and stdio service.

## Stable results

Core operations return `OperationResult`, with a status (`ok`, `partial`, `error`), optional three-valued verdict (`proved`, `refuted`, `unknown`), explicit unknowns and assumptions, and versioned metadata. Legacy APIs translate these objects to their historical return types. A completed run is not itself a proof certificate: the service only exposes a certificate when a checkable proof object exists.

`SourceDocument` uses Python character offsets for spans and carries a SHA-256 source digest. Tree-sitter byte offsets are converted once at the parser bridge. `PathContract.identity` includes normalized guard text and observable outcome semantics, and it is intentionally independent of the optional refinement/solver layer. Semantic equivalence remains a separate analysis operation.

## Shared analysis and scaling

`pegrex.sessions.AnalysisSession` owns one normalized tree per source/language/configuration. Call graph, contracts/CFG, complexity, SAST/taint, test synthesis, and LSP document analysis can consume that tree without reparsing. Persistent entries use the full SHA-256 source digest plus parser/analyzer implementation versions and normalized configuration. Paths are diagnostic metadata only. `IncrementalSummaryCache` invalidates changed files and transitive reverse dependents.

Expression nodes in `ir` and `sym` are immutable and hash-consed. Canonicalization, immutable linear forms, and Fourier–Motzkin implication probes are memoized. `PathEnumerator.enumerate_bounded()` returns either a complete path set or `UNKNOWN` with no partial paths; `path_summaries_bounded()` and bounded session contracts preserve the same rule. `LinearBackend.entails_with_status()` distinguishes `entailed`, `not_entailed`, and resource `unknown`; the legacy boolean API fails closed. Per-file deadlines, solver query budgets, path caps, sorted successor traversal, and deterministic octagon widening make resource behavior explicit and reproducible.

Converted security packs are deduplicated only by canonical rule ID plus complete semantics. Same-ID semantic variants remain independently executable. `pegrex.rules` records pack/upstream/version provenance and reports exact duplicates, disabled rules, and language-inapplicable rules; rejected rules remain scanner UNKNOWNs.

Process parallelism is opt-in through `pegrex.concurrency`, with sequential defaults for small repositories and explicit `spawn` contexts on Linux, Windows, and macOS. Directory call graphs expose `--jobs` and `--benchmark`. CLI parser construction and dispatch remain in `pegrex.cli`; command implementations live in `pegrex.commands.analysis`, `.verification`, and `.tooling`.

## Security execution and evidence

`pegrex.harness` is an authorization boundary, not a shell parser. Shell plans contain structured argv only; canonicalization produces the executable identity before policy matching. The same boundary rejects shell chaining/quoting tricks, environment expansion, absolute and parent-traversal paths, symlink components, indirect launchers, alternate executable spellings, and Unicode confusables. Filesystem checks are containment checks at authorization time, not a claim of race-free mutation.

`tools.secaudit` snapshots its rule catalog for a scan and emits `pegrex.security-scan.v1`. Provenance combines the full source digest, exact content-defined catalog versions, upstream pack versions/digests, declared and installed parser versions, scanner limits, and OSV status. Taint findings retain concrete source and sink locations. `pegrex.export.to_sarif` translates this common evidence model to SARIF 2.1.0 with stable rule/fingerprint identities, CWE/OWASP and confidence properties, related locations, code flows, and justified in-source suppressions. Accepted suppressions remain visible and are the only findings excluded from CI gates.

`pegrex.sca` treats OSV data as evidence with provenance. Reproducible scans read an explicit local query snapshot or cache with network disabled. Missing entries and query failures are UNKNOWN; they never become an authoritative empty vulnerability list. Complete online query sets can be captured to a content-hashed snapshot and replayed offline.

## Adding an operation

Keep domain/result types in `pegrex.core`; expose a lazily loaded adapter in `CoreEngine` and enforce capabilities through `pegrex.languages`. Public APIs should be thin compatibility wrappers. Never encode an unknown result as success, and do not represent a completed analysis as a certificate unless an independently checkable proof artifact was emitted.
