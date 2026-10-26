# PegRex architecture: stable core and registered frontends

## Dependency direction

PegRex is organized in four layers. Dependencies point inward; the stable core does not import optional parser bindings, solver backends, audit catalogs, or agent runtimes during module import.

1. **Public adapters** — `pegrex.api`, `pipeline.py`, `service.py`, and the CLI preserve historical call shapes and wire formats. `pegrex.toolsapi` provides the additive v2 manifest/invocation boundary; `pegrex.commands.production` exposes it and core dispatch through the CLI.
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

`SourceDocument` uses Python character offsets for spans and carries a SHA-256 source digest recomputed from the UTF-8 text; forged caller-supplied digests are rejected. Tree-sitter byte offsets are converted once at the parser bridge. `PathContract.identity` includes normalized guard text and observable outcome semantics, and it is intentionally independent of the optional refinement/solver layer. Semantic equivalence remains a separate analysis operation.

`CoreEngine.execute()` is the non-throwing operation-dispatch adapter: malformed envelopes, unsupported operations, and adapter exceptions become structured error/UNKNOWN results, while direct historical methods retain their exception contracts. Only explicitly confirmed counterexamples promote verification to REFUTED. `pegrex.toolsapi` adds declarative argument schemas, lazy implementation loading, workspace path/symlink confinement, file hashes, and versioned evidence envelopes. Its registry has no raw-shell operation and no real-workspace mutation path.

## Shared analysis and scaling

`pegrex.sessions.AnalysisSession` owns one normalized tree per source/language/configuration. Call graph, contracts/CFG, complexity, SAST/taint, test synthesis, and LSP document analysis can consume that tree without reparsing. Persistent entries use the full SHA-256 source digest plus parser/analyzer implementation versions and normalized configuration. Paths are diagnostic metadata only. `IncrementalSummaryCache` invalidates changed files and transitive reverse dependents.

Expression nodes in `ir` and `sym` are immutable and hash-consed. Canonicalization, immutable linear forms, and Fourier–Motzkin implication probes are memoized. `PathEnumerator.enumerate_bounded()` returns either a complete path set or `UNKNOWN` with no partial paths; `path_summaries_bounded()` and bounded session contracts preserve the same rule. `LinearBackend.entails_with_status()` distinguishes `entailed`, `not_entailed`, and resource `unknown`; the legacy boolean API fails closed. Per-file deadlines, solver query budgets, path caps, sorted successor traversal, and deterministic octagon widening make resource behavior explicit and reproducible.

Converted security packs are deduplicated only by canonical rule ID plus complete semantics. Same-ID semantic variants remain independently executable. `pegrex.rules` records pack/upstream/version provenance and reports exact duplicates, disabled rules, and language-inapplicable rules; rejected rules remain scanner UNKNOWNs.

Process parallelism is opt-in through `pegrex.concurrency`, with sequential defaults for small repositories and explicit `spawn` contexts on Linux, Windows, and macOS. Directory call graphs expose `--jobs` and `--benchmark`. CLI parser construction and dispatch remain in `pegrex.cli`; command implementations live in `pegrex.commands.analysis`, `.verification`, and `.tooling`.

## Security execution and evidence

`pegrex.harness` is an authorization boundary, not a shell parser. Shell plans contain structured argv only; canonicalization produces the executable identity before policy matching. The same boundary rejects shell chaining/quoting tricks, environment expansion, absolute and parent-traversal paths, symlink components, indirect launchers, alternate executable spellings, and Unicode confusables. Filesystem checks are containment checks at authorization time, not a claim of race-free mutation.

`tools.secaudit` snapshots its rule catalog for a scan and emits `pegrex.security-scan.v1`. Provenance combines the full source digest, exact content-defined catalog versions, upstream pack versions/digests, declared and installed parser versions, scanner limits, and OSV status. Taint findings retain concrete source and sink locations. `pegrex.export.to_sarif` translates this common evidence model to SARIF 2.1.0 with stable rule/fingerprint identities, CWE/OWASP and confidence properties, related locations, code flows, and justified in-source suppressions. Accepted suppressions remain visible and are the only findings excluded from CI gates.

`pegrex.sca` treats OSV data as evidence with provenance. Reproducible scans read an explicit local query snapshot or cache with network disabled. Missing entries and query failures are UNKNOWN; they never become an authoritative empty vulnerability list. Complete online query sets can be captured to a content-hashed snapshot and replayed offline.

## Advanced dataflow and deployment analysis

`pegrex.ssa` provides immutable-by-value SSA assignments, globally unique versions, branch phi nodes, and explicit loop-backedge widening. Expression rendering deep-copies AST nodes so shared syntax trees are never mutated. `pegrex.flow` builds structured CFGs and computes fixed-point abstract states. Symbolic parameter origins are instantiated at cross-module call sites; recursive summary cycles are explicitly widened. Branch guards and direct sanitizers suppress only the paths and sink rules they satisfy. Secret rules classify log, telemetry, URL, process-argument, and network sinks, while context rules can recognize safe literal keywords, state arguments, and context managers. These analyses are available as separate APIs; their addition does not silently change the legacy scanner contract.

`pegrex.effects` distinguishes process launch from I/O, concurrency, mutation, nondeterminism, and other effects, and preserves transitive provenance. `pegrex.concurrency_analysis` exposes shared accesses, common-lock race candidates, lock-order cycles, async/thread targets, and explicit start/join/result/await happens-before evidence. Alias and external synchronization coverage remains partial and is reported as such.

`pegrex.policy` evaluates declarative JSON policies without evaluating Python expressions. Unsupported operators, empty selections, missing parsers, and parse failures are UNKNOWN. IaC adapters cover IAM/Kubernetes JSON or YAML and documented Terraform/Dockerfile subsets; assumption comparisons report deployment mismatches rather than claiming full deployment equivalence.

## Evidence bundles and analyzer workers

`pegrex.auditbundle` writes deterministic ZIP evidence with source and artifact SHA-256 hashes, normalized configuration, exact tool/parser versions, coverage, reports, and an optional explicit OSV snapshot. It contains no wall-clock timestamp or absolute source root. Verification separates artifact tampering from subsequent source drift. Missing coverage remains UNKNOWN.

`pegrex.workers` runs SSA, effect, taint/secret, and grammar-compilation analyses in argv-only subprocesses with empty environments, CPU/address-space/file limits, wall-clock cancellation, and bounded input/output. Source is parsed as data and never executed. This is process/resource isolation, not a container, network, or filesystem-confinement claim; unsupported platforms return UNKNOWN rather than falling back to in-process analysis.

Loop-summary evidence interprets only validated integer arithmetic and comparison ASTs, with an iteration cap; it never executes analyzed loop source. Concolic tracing executes the operator-selected function but observes branches through the same restricted evaluator, so an opaque predicate is not evaluated a second time. The CLI `concolic` command and Python certificate checker remain explicit operator-code-execution interfaces. The legacy MLIR pipeline adapter consumes the versioned compiler-IR parser and refuses incomplete/multi-function input instead of constructing regex-derived or single-successor proof CFGs.

## Agent evidence and proof-gated change control

`pegrex.agenttools` exposes contract queries, verifier outcomes, and confirmed counterexamples in `pegrex.agent-evidence.v1` envelopes with source identities. `pegrex.policygate` applies fail-closed `SecurityProfile` selection to UNKNOWN reasons, categories, and rule IDs; explicit allowances remain visible as accepted UNKNOWNs rather than becoming clean evidence.

`pegrex.patchgate` performs edits in a disposable staged repository. Semantic certificates, required invariants, argv-only tests, optional candidate rechecks, and the selected security policy must all allow the change before an atomic target replacement. `pegrex.editaudit` durably records original and proposed source, unified diffs, tests, proof attempts, and the final decision for accepted and rejected attempts. `pegrex.repairloop` reruns the same finding analyzer on each staged candidate and requires the target finding to decrease without increasing any other finding identity.

`pegrex.kernel` is the minimal trusted certificate checker. It uses only standard-library JSON, SHA-256, bounded structural validation, and canonical contract-set equality. It imports no analyzer, parser, solver, or PegRex schema module and does not trust a producer's `proved` claim. REFUTED certificates and unsupported or malformed evidence remain UNKNOWN because counterexample execution is outside this kernel.

`pegrex.multiagent` separates candidate generation, patch generation, counterexample search, and independent checking into typed role-evidence records. A checker may not be either generator callable. Role output feeds the patch gate as an additional candidate check; it never grants a separate write path.

## Contract memory, semantic impact, and planning

`pegrex.repomemory` builds persistent, content-identified repository memory from incremental API contracts, invariants, imports, architectural boundaries, and known limitations. `pegrex.semgraph` derives a live graph of modules, functions, contracts, and invariants, with forward dependency and reverse impact traversal. Refreshes report changed and impacted nodes plus memory UNKNOWNs.

`pegrex.planner` ranks proposed changes by benefit, reachable reverse impact, uncertainty, and proof effort. Missing targets or invalid numeric inputs remain unranked UNKNOWN rows. The plan orders work; it is not evidence that a transformation is safe and does not bypass proof-gated application.

## Verification evidence, replay, and restricted resource proofs

`pegrex.pathrefine` removes a path only on an UNSAT result or a same-behavior dominance proof and retains the path, dominator, method, and reason. Undecided feasibility or implication keeps the path and emits UNKNOWN. `pegrex.witness` minimizes concrete symbolic models while rechecking the original linear constraints and optional reproducer after every candidate shrink; it does not delta-debug source text.

`pegrex.analyzermutation` runs baseline and deliberately weakened parser, solver, and rule negative controls. A control is killed only when the baseline detects the defect and the weakened analyzer does not. `pegrex.smtlib` exports deterministic QF_LIA SMT-LIB without needing a solver and offers optional Z3 parsing/cross-checking. `pegrex.proofreplay` is a standalone standard-library checker for canonical equality certificates and optional source hashes; it does not import the original analyzer or invoke a solver.

`pegrex.statemachine` checks declarative transitions and invariants with concrete traces. Full finite-graph exhaustion is PROVED; invariant violations are REFUTED; depth/state caps and undecided invariants are UNKNOWN. `pegrex.resourcebounds` handles structured range loops and simple decreasing integer variants. Its allocation metric is allocation sites, not byte-exact memory. `pegrex.compilerdiff` compares complete Python artifacts from compiler upgrades or optimization changes with the existing three-valued semantic verifier; unsupported artifact forms remain UNKNOWN.

## Framework security and software-supply-chain evidence

`pegrex.frameworkpacks` supplies versioned web, database, shell, deserialization, templating, and cloud source/sink packs. `pegrex.securitycontracts` evaluates declared source-category/sink-category prohibitions and required transformations over fixed-point flow evidence. Flow findings retain exact sink-rule semantics, rule-pack identity, matched AST/source spans, origin-to-sink chains, and evidence strength. Secret analysis covers environment/configuration credentials and log, telemetry, URL/payload, process, and network sinks. These results are scoped static evidence, not assertions about unmodeled frameworks.

`pegrex.reachability` augments the existing OSV inventory with static Python import/call reachability. A vulnerable symbol must be declared before a call can be classified reachable. `not-observed` is not a proof of absence, and missing symbol data or incomplete repository coverage is UNKNOWN. Installed inventory and reachability remain separate facts.

`pegrex.sbom` generates CycloneDX 1.5 or SPDX 2.3 documents from supported lockfiles, including dependency edges, available integrity hashes, license declarations, and offline source provenance. Missing licenses remain `NOASSERTION`/UNKNOWN. `pegrex.lockpolicy` checks exact versions, cleartext URLs, URL hashes, VCS commit pinning, and lockfile integrity. Typo-similarity is a review signal, not a maliciousness verdict.

`pegrex.buildprovenance` emits in-toto Statement v1 with a SLSA provenance v1 predicate, structured argv, verifiable output subjects, and resolved dependency materials. Verification recomputes available subject/material hashes and detects drift. Unsigned statements do not authenticate a builder, hermeticity, or a SLSA level.

## Attack paths, exploitability, and isolated repair evidence

`pegrex.policy` reports the exact IaC parser and confidence for Terraform, Kubernetes, Helm, Dockerfile, IAM, and NetworkPolicy analysis. Helm expressions are masked only for static YAML structure; template evaluation is unavailable and remains UNKNOWN. Parse failures retain the same parser/confidence provenance and cannot become clean results.

`pegrex.attackgraph` joins assets, identities, exposures, dependencies, code origins, and reachable sinks or vulnerable calls. Path enumeration is bounded; reaching a path/depth cap returns UNKNOWN with no partial path list. `pegrex.exploitability` separates `pattern-match`, `confirmed-test`, `symbolic-witness`, and `sandboxed-reproduction`. The strongest confirmed level and missing rungs are evidence labels, not exploit probabilities.

`pegrex.pocsandbox` executes declared files and argv only inside an ephemeral bubblewrap namespace with empty credentials/environment, no network namespace, and `prlimit` resource bounds. Missing binaries, namespace setup failure, unsafe paths, raw shell text, and timeouts fail closed. In particular, process/rlimit isolation is never substituted for this boundary. `pegrex.harnessmutation` combines canonical safe-plan checks with mutation-based bypass cases; syntax/launcher confinements must survive an allow-all policy mutation, while policy-only denials must be killed by it.

`pegrex.regressionmemory` registers a fixed finding only after the exact rule fires on the vulnerable source and is absent from the fixed source. It persists both a fixed-finding pytest and a vulnerable-source rule-negative control, with content hashes and tamper verification. `pegrex.contextcompiler` budgets repository memory into whole symbol/contract/invariant/dependency/test records and mandatory UNKNOWN markers. If mandatory uncertainty cannot fit, compilation is UNKNOWN rather than silently lossy.

## Agent task lifecycle, conjectures, and decision provenance

`pegrex.a2atasks` supplies explicit task IDs, budgets, deadlines, evidence, cooperative cancellation, partial results, and `execution_active` state. Late results become timeout/partial evidence; Python threads are not described as forcibly killable. `pegrex.specproposals` creates LLM proposals as unevaluated conjectures. Only independent proof evidence can prove one, only a confirmed counterexample can refute one, and all other outcomes remain UNKNOWN.

`pegrex.repairloop.repair_with_sandboxed_differential` adds bounded before/after sandbox observations and independent staged validation to the existing analyzer/policy patch gate. Matching observations are passed differential tests, not semantic-equivalence proofs. Independent validation is repeated against the real post-fix file; if it is not PROVED or the applied bytes differ from the approved candidate, the original source is restored and the result is UNKNOWN. Candidate and rejected-attempt evidence remains in the repair trail and edit audit.

`pegrex.decisionlog` explains every matching and nonmatching harness rule, normalized argv/path data, and allow/refuse/default-deny reason. JSONL records are SHA-256 hash-chained and verification detects record or chain tampering.

## Modernization, protocol, and compiler-IR evidence

`pegrex.modernization` extracts COBOL/Fortran contracts and emits Python, Rust, or Go candidates, then independently reanalyzes the emitted target. Contract equality, declared numeric/overflow semantics, and record data-layout compatibility are separate evidence layers. Python unbounded integers and Go fixed-width wrap arithmetic can be proved only in their declared scopes; plain Rust arithmetic remains UNKNOWN because overflow depends on the build profile. Missing declarations are UNKNOWN, overlapping layouts are REFUTED, and a validated nonempty source layout is not silently treated as proved target lowering.

`pegrex.roundtrip` generates deterministic Python-server and Go-client stubs and separately checks static OpenAPI drift and old/new runtime observations. Static agreement without operation-covering runtime cases is UNKNOWN; canonical result mismatches are REFUTED. `pegrex.formalprotocols` uses strict JSON, URL, CSV, INI, S-expression, and properties parsers. Success proves only the documented well-formedness/schema fragment, while duplicates, malformed escapes, inconsistent rows, and trailing input remain UNKNOWN.

`pegrex.compilerir` registers exact LLVM 17/18, Rust MIR, and MLIR grammar versions. CFG edges come only from parsed terminators, never regular-expression control-flow guesses. Missing blocks/targets/terminators and unsupported versions or terminators are UNKNOWN; a parsed graph is not a semantic-equivalence proof. `pegrex.proverbridge` exports Why3, SMT-LIB, Lean, and Coq obligations with `proof_status: "not-checked"`. External PROVED/REFUTED status requires explicit proof or confirmed-counterexample evidence.

## Smart-contract and source-bounded compliance evidence

`pegrex.smartcontract` keeps heuristic Solidity source checks, PUSH-data-aware EVM bytecode checks, formal claims, and local-EVM tests in independent sections. Pattern absence is not proof; formal success requires proof evidence; local tests require a runner that confirms local execution. Missing EVM support is UNKNOWN and one layer never substitutes for another.

`pegrex.evidencepack` maps executable flow contracts and source observations to declared controls. Organizational, procedural, legal, and runtime controls are explicitly not provable from source and remain UNKNOWN. Packs contain technical evidence only, with no legal conclusion, certification, attestation, or compliance claim.

## Repository twin, drift, incidents, and trace guidance

`pegrex.digitaltwin` joins call/ownership graphs, repository contracts and dependencies, supplied change history, and declared risk exposures into a content-identified twin. Function impact is distinguished from module-level dependency impact. `pegrex.drift` compares intended boundaries with import and internal-call edges; confirmed unintended coupling is REFUTED while incomplete evidence remains UNKNOWN.

`pegrex.incident` constrains candidate contracts with runtime events, classifies trace feasibility, and evaluates patch candidates without applying them. `pegrex.traceguided` prioritizes feasible unseen or high-risk symbolic paths using declared traces, retains unseen paths, and returns UNKNOWN without a partial ranking when the path budget is exceeded. Observed traces never make unobserved paths impossible in either module.

## Proof-carrying releases and continuous assurance

`pegrex.releaseproof` joins content-identified API contracts, an offline dependency SBOM, an in-toto/SLSA-shaped build attestation, and semantic diff evidence from a previous root. Its machine-readable UNKNOWN summary is part of the release identity and is reverified with available upstream artifacts. Unsigned provenance authenticates neither the builder nor hermeticity, so it cannot be promoted to an authenticated release claim.

`pegrex.assurancegraph` represents API-contract, access-policy, taint-invariant, and migration-property claims. Every dependency edge names its evidence identity and exact upstream SHA-256. An exact content mismatch invalidates dependent PROVED claims to UNKNOWN; unchanged content retains its prior evidence. `pegrex.changebudget` accounts for public-contract, security-surface, dependency, cognitive-complexity, and UNKNOWN-region changes. Budget excess is REFUTED; a complete summary is not itself merge approval.

## Executable compliance and semantic release identities

`pegrex.compliancemap` joins declared data classifications, source/sink traces, retention/deletion functions, and infrastructure controls into a bounded queryable graph. Static lifecycle mappings do not prove operational deletion or retention. Legal interpretation is either `human-review-required` or `human-reviewed`, and in both cases `proved_by_code` is false.

`pegrex.semanticchecksum` canonically serializes normalized contracts, explicit type/domain assumptions, and location-independent effect summaries. Surface comments and coordinates do not affect the checksum. A mismatch identifies changed components but remains UNKNOWN without confirmed semantic evidence. `pegrex.researchcapsule` packages a finding, minimized vulnerable source, exploit preconditions, an unexecuted no-network/no-credentials sandbox recipe, fixed source, regression/negative-control tests, and proof/witness material in a deterministic content-addressed ZIP. Verification rechecks hashes and the original finding control without claiming recipe execution.

## Pre-merge impact and secure action brokerage

`pegrex.impact` applies proposed source only to a staged repository copy. It reports potentially invalidated contracts, architecture policies, generated Python/Go stubs, data-flow findings, and downstream functions/modules. Generated-stub drift still requires runtime round-trip evidence, and simulation never authorizes a merge.

`pegrex.actionbroker` separates intent serialization, default-deny policy authorization, ephemeral execution, and hash-chained evidence. Authorization is bound to the exact plan, policy, and workspace and must have been issued by the local policy engine; revoked or substituted capabilities cannot execute. Shell actions use argv-only ephemeral sandboxing. Direct reads/writes record actual paths and hashes; shell filesystem mutations remain UNKNOWN when the sandbox does not enumerate them. Network disablement requires sandbox evidence. The recorder's SHA-256 chain is local integrity evidence, not a signed attestation.

## Adding an operation

Keep domain/result types in `pegrex.core`; expose a lazily loaded adapter in `CoreEngine` and enforce capabilities through `pegrex.languages`. Public APIs should be thin compatibility wrappers. Never encode an unknown result as success, and do not represent a completed analysis as a certificate unless an independently checkable proof artifact was emitted.
