# PegRex public contracts

This document characterizes the compatibility surface protected by `tests/test_public_contracts.py` and the existing API, service, CLI, and stable-architecture suites. It describes behavior, not a claim that every analyzer is complete.

## Versions and value domains

- Core serialized models carry `schema: "pegrex.core.v1"`; `CoreEngine.schema` is `"pegrex.core-engine.v1"`; the legacy capability matrix uses `"pegrex.language-capabilities.v1"`. Soundness reports use `"pegrex.soundness.v1"`.
- Verification verdicts are exactly `proved`, `refuted`, and `unknown`. A missing proof or unconfirmed witness is `unknown`, not `refuted` and never `proved`.
- Operation statuses are `ok`, `partial`, and `error`. Partial results explain incomplete coverage in `unknowns`.
- Source spans are zero-based, end-exclusive Python character offsets, including at adapter boundaries backed by Tree-sitter UTF-8 byte offsets.

## Stable core models

`SourceDocument.text`, `.language`, `.path`, and `.sha256` define an immutable source. The digest is recomputed from UTF-8 text; a caller-supplied mismatch is rejected as forged provenance. Its `to_dict()` emits `schema`, `path`, `language`, `sha256`, `characters`, and `utf8_bytes`.

`PathContract` is an explicit `(constraints, outcome)` record with optional `function`, `source_hash`, and metadata. Identity includes outcome and the other identity fields; constraints are sorted and whitespace-normalized. `to_dict()` emits `schema`, `constraints`, `outcome`, `function`, `source_hash`, `metadata`, and `identity`.

`OperationResult.to_dict()` emits exactly `schema`, `operation`, `status`, `verdict`, `data`, `unknowns`, `assumptions`, and `metadata`. Contract rows in `CoreEngine.extract_contracts()` use the `PathContract` shape above.

## Core dispatch and Tools API v2

`CoreEngine.api_version` is `"2.0"`. `operations()` returns the registered dispatch metadata. `execute(operation, arguments=None)` supports `parse`, `contracts`, `contracts_file`, `audit`, `call_graph`, `verify_patch`, `capabilities`, and `soundness`, returning `OperationResult` instead of raising across the dispatch boundary. Unknown operations, non-object argument envelopes, invalid arguments, and implementation exceptions become `status: "error"`, `verdict: "unknown"` with structured diagnostics. Direct methods keep their established exception behavior.

`pegrex.toolsapi.list_tools()` returns `pegrex.tools-api-manifest.v2`; `invoke(name, arguments, workspace=...)` returns `pegrex.tools-api-envelope.v2`. Tool specifications declare JSON-shaped required/optional parameters and path arguments. Invocation rejects unknown operations, unknown/missing arguments, wrong container/scalar types, workspace traversal, absolute paths outside the workspace, and symlink escapes. File identities include SHA-256 and byte size. Implementations import lazily. The registry includes core analysis, release verification, assurance invalidation, semantic budgets, compliance maps, semantic checksums, capsule verification, staged impact simulation, and broker evidence verification; it exposes no raw-shell operation and does not mutate the real workspace.

`pegrex.api.synthesize_tests_from_coverage(source, lcov, fn_name=None)` is the unambiguous coverage-guided API; `synthesize_from_coverage` is its compatibility alias. `pegrex.api.synthesize` remains the separate program-synthesis API, and the `tests` CLI command uses the coverage-guided operation.

## Legacy Python API

The compatibility layer remains valid alongside the typed core:

- `pegrex.api.contracts(path, lang=None) -> list[tuple[frozenset[str], str]]`.
- `pegrex.api.audit(path, lang=None) -> list[dict]` preserves exactly `id`, `severity`, `confidence`, `line`, `evidence`, `message`, `kind`, and `function`. Rich location, mapping, evidence, provenance, and suppression fields belong to `tools.secaudit.audit()` and `audit_report()`. `kind: "unknown"` is incomplete analysis, not a clean result. Accepted suppressions set `suppressed: true` and a standard suppression record; they remain visible in rich reports.
- `pegrex.harness` shell actions accept only structured `argv`. `normalize_argv()` returns the canonical executable/argument identity used by policy matching. Raw shell text, metacharacters, environment expansion, absolute/home paths, shell/launcher executables, and non-canonical Unicode are refused. File actions reject absolute paths, traversal, and symlink components; `base_dir=` defines the workspace for the check.
- `pegrex.sca.scan(path, offline=..., snapshot=...)` returns `pegrex.osv-scan.v1`. `status: "complete"` means every dependency received an authoritative snapshot/cache/API answer. Missing or failed lookups produce `status: "unknown"` and per-dependency `unknowns`; an empty vulnerability list alone is not a coverage claim.
- `pegrex.smt.auto_feasible(atoms) -> bool | None`: `None` means that no available backend can decide.
- `pegrex.cegis.repair()` retains its trail statuses; syntactically invalid Python proposals use `error`. `llmcegis` presents those as `invalid`.

New callers should prefer `CoreEngine` where typed status and unknown reporting are needed.

## Shared sessions and resource results

- `AnalysisSession(source, language, ...)` lazily shares one normalized tree across registered consumers. Its digest is full SHA-256 content; optional `path` never affects cache identity. `analyze()` returns `pegrex.analysis-session.v1`, with per-analyzer `status: "ok"` or `"unknown"` and resource diagnostics.
- `AnalysisCache` identities include content, analyzer set, implementation version, and normalized configuration. `IncrementalSummaryCache.update()` returns the changed file and all transitive reverse dependents whose summaries were invalidated.
- `PathEnumerator.enumerate_bounded()` returns `PathEnumeration`. `complete: true` means `paths` is complete; otherwise `verdict == "unknown"`, `paths == []`, and `unknowns` explains the cap/deadline. The legacy list API raises `PathExplosion` rather than returning a truncated list.
- `LinearBackend.entails_with_status()` returns `entailed`, `not_entailed`, or `unknown`, plus query/resource details. Legacy `entails()` returns true only for `entailed`.
- `pegrex.rules` and `Auditor.coverage(language)` expose active, duplicate, disabled, inapplicable, rejected, and provenance metadata. Deduplication never collapses same-ID rules with different executable semantics. `catalog_version` is the SHA-256 identity of the exact executable catalog snapshot.
- `Auditor.scan_report()` / `audit_report()` return `pegrex.security-scan.v1` with full source SHA-256, declared and installed parser versions, exact rule catalog identities, scanner configuration, and OSV snapshot status. Source audits never need network access. `parser_provenance(language)` exposes the parser identity independently.
- `pegrex.concurrency.process_map()` is sequential by default and for small inputs. Explicit workers use spawn-based processes and preserve input order. `benchmark_process_map()` verifies sequential/parallel result equality and reports overhead.

## CLI

`pegrex audit FILE [--lang LANG] [--json|--sarif] [--out PATH]` prints a report and exits 0 by default, even when findings exist. JSON output has `file`, `findings`, `total`, active/suppressed counts, and exact provenance. SARIF 2.1.0 includes stable rule IDs, CWE/OWASP mappings, confidence and `security-severity`, source/sink related locations and code flows, fingerprints, and accepted suppression justifications for GitHub Code Scanning. `export FILE --format sarif` uses the same exporter.

- `--fail-on critical|high|medium|low|info` exits 1 when an unsuppressed, non-unknown finding meets the threshold.
- `--fail-on-unknown` exits 2 when unsuppressed scanner coverage is incomplete. The unknown gate takes precedence over the severity gate.
- Inline `# pegrex:ignore RULE-ID -- JUSTIFICATION` (or the corresponding `//` comment) on the finding/preceding line creates an accepted in-source suppression. Missing justifications do not suppress and are reported as suppression errors.
- Without either option, audit remains explicitly report-only.
- `tools/secaudit.py` exposes the same policy.
- `audit-bounded` emits JSON with `verdict: "ok"` or `"unknown"`, `latency_ms`, and either `findings` or `reason`; deadline overrun cancels the worker.
- `soundness [--language ID]` prints the canonical frontend manifest and trust policy as JSON. An unknown language is an error, not an empty or assumed-capable plugin.
- `rules [--lang ID] [--json]` reports deduplicated rule counts, provenance, and active/disabled/inapplicable coverage.
- `callgraph --dir PATH [--jobs N] [--benchmark]` keeps one worker by default; process execution is opt-in and benchmark output goes to stderr so DOT/ASCII stdout remains valid.
- `osvscan LOCKFILE [--offline] [--osv-snapshot PATH] [--snapshot-out PATH] [--fail-on-unknown]` never silently converts missing vulnerability evidence to clean. A snapshot records its upstream ID and full file SHA-256; `--snapshot-out` captures only complete query sets for deterministic offline reuse.
- `tools [--name NAME]` lists or selects Tools API v2 metadata. `tool NAME [--workspace PATH] [--input JSON|@FILE|--input-file FILE]` emits the versioned tool envelope. `engine list` lists core operations; `engine OPERATION` emits the core result.
- Production operation errors exit 1. `--fail-on-unknown` exits 2 for UNKNOWN or partial evidence; completed REFUTED analysis is not itself a process failure. Top-level CLI failures emit `pegrex.cli-error.v1` on stderr without a traceback.
- `attest` and insurance quote generation require explicit `--key`; invariant-market publish/import likewise requires an explicit non-empty key. No implicit demo key is accepted.

## Stdio service

`service.py` reads one JSON object per input line and writes one JSON object per output line. Blank lines are ignored. Exceptions during request handling become `{"ok": false, "error": repr(...)}`.

- `ping` -> `{"ok": true, "pong": true}`.
- `parse` with `language` and `source` -> `ok`, `ast`, `language`, `node_count`. AST nodes contain `tag`, `pos`, `endpos`, and `children`.
- `contracts` -> `ok`, `status`, `contract`, `unknowns`, `metadata`; each contract row is `[constraints, outcome]`.
- `callgraph` -> `ok`, the core result fields, `ascii`, and `edges`.
- `gaps` -> `ok` and `gaps`, with `constraints` and `suggestion` per gap.
- `fix` -> `ok`, finding-local `focus`, and `context_window`.
- `verify` executes the pipeline but deliberately returns `verified: false`, `certificate: null`, a `certificate_note`, `status`, `log`, and `name`: completion is not promoted to an independently checkable proof.
- `soundness` with an optional `language` -> `ok` and `soundness`, containing the same report as the CLI and core.
- Unknown methods return `ok: false` and `error`.

## Language registry

`pegrex.languages` owns aliases, extensions, parser bindings and versions, capabilities, rule inheritance, contract frontends, coordinate conversion, normalization, error policy, CFG adapters, supported constructs, lowering coverage, security packs, maturity, and known unsupported cases. `language_capabilities()` and `capability_matrix()` preserve the original 16-key wire shape and remain sorted by canonical language name. `frontend_manifest()` and `plugin_registry()` expose the richer canonical manifest without changing that legacy contract. Parser availability does not imply contracts, proof, audit, or taint support. Unsupported capabilities raise `CapabilityError` at the core boundary.

`soundness_report()` and `CoreEngine.soundness()` return the `pegrex.soundness.v1` report. Its `policy` states verdict, coordinate, counterexample, scanner-coverage, and completion rules; `plugins` contains one or all canonical manifests. This is a capability and limitation report, not a runtime proof that optional parser dependencies are installed. `stable` maturity means a supported production adapter with declared limits, not complete language semantics; `parse-only` frontends never imply contracts or proof.

## Analysis limits

The legacy scanner taint remains source-order and heuristic, with light interprocedural propagation; it is not field-sensitive proof. Strict unresolved flows remain `unknown`. Scanner input limits, rejected rules, parser gaps, match caps, and regex timeouts likewise produce unknown coverage findings rather than silent clean results. Context-insufficient converted rules are disabled with explicit `disabled_reason` and remain visible in coverage/provenance; this is not silent finding suppression.

`concolic` CLI and certificate checking intentionally execute operator-selected local code and must not be presented as safe handling of untrusted source. Concolic branch observation uses restricted arithmetic/boolean evaluation, so opaque predicates are UNKNOWN and are not re-executed. Loop-summary concrete evidence uses a restricted AST interpreter; analyzed loop source, return expressions, calls, attributes, decorators, and unsupported signatures are never executed. HTTP LLM proposers accept only HTTP(S) endpoints without embedded credentials.

New callers can opt into the following additive APIs without changing that legacy behavior:

- `pegrex.ssa.build_ssa(source, function=None)` returns `pegrex.ssa.v1`, with assignments, returns, branches, and explicit unsupported-construct/widening UNKNOWNs.
- `pegrex.flow.analyze_source()`, `.analyze_modules()`, `.analyze_repository()`, and `.analyze_secrets()` return `pegrex.interprocedural-taint.v1`. Reports include CFG/summary fixed-point status, recursion widening, symbolic summaries, findings, and UNKNOWNs. SourceRule/SinkRule patterns are regular expressions; sanitization and context rules apply only to their declared sinks.
- `pegrex.policy.check_policies()` returns `pegrex.policy-checks.v1`; `.analyze_iac()` returns `pegrex.iac-analysis.v1`. Unsupported policy operators, formats, assumptions, and parse failures are UNKNOWN, never clean.
- `pegrex.auditbundle.create_audit_bundle()` and `.verify_audit_bundle()` implement `pegrex.reproducible-audit-bundle.v1`. Identical inputs produce identical bytes; `stable: false` means source drift, while `ok: false` means missing/tampered evidence or an unreadable bundle.
- `pegrex.workers.run_analyzer_worker()` returns `pegrex.analyzer-worker.v1`. Worker status `ok` applies only to the requested analysis; timeouts, resource refusal, invalid output, and parser failures return `unknown` with no result. The documented isolation scope is process/rlimits, not a container.
- New flow findings use the common SARIF exporter. Source locations retain their own files and lines, and SARIF properties include flow category, sanitizers, and call contexts.

## Fail-closed policy and typed agent evidence

- `SecurityProfile` defaults to `fail_on_unknown=True` and `require_proved=True`. `unknown_reasons`, `unknown_categories`, and `unknown_rules` select policy-relevant UNKNOWNs; `allow_unknown_reasons` records explicit exceptions in `accepted_unknowns`. `evaluate_security_policy(report, profile)` returns `pegrex.security-policy-decision.v1`; it never removes the underlying UNKNOWN evidence.
- `query_contracts(path, language=None, function=None)` returns `pegrex.agent-evidence.v1` containing versioned `pegrex.contract.v1` rows and source path/byte/SHA-256 provenance. Query and extraction failures return empty data with UNKNOWN evidence.
- `verify_change(before_path, after_path, claim="equivalent")` returns a typed `pegrex.certificate.v1`. `find_counterexample()` exposes a counterexample only when `confirmed is true`; an unconfirmed witness is not a behavioral refutation.
- `agent_tool_manifest()` returns `pegrex.agent-tools.v1` and describes the typed tool surface.

## Certificates, edit gates, and repair

- `check_certificate(certificate)` returns `pegrex.kernel-check.v1`. Only supported version-1 `equivalent`/`patch-equivalent` certificates with verdict `proved`, no UNKNOWNs, bounded well-formed evidence, exactly equal canonical contract sets, and matching optional contract hashes pass. Malformed, oversized, differing, forged, REFUTED, or unsupported certificates do not pass.
- `promote_counterexample()` and `promote_patch_counterexample()` require `counterexample.confirmed is true`; missing or false confirmation cannot become a regression certificate. Expected-observable promotion additionally requires an explicit `expected` value.
- `apply_patch_gated(target, proposed_source, ...)` returns `pegrex.patch-gate.v1`. It stages the whole candidate before target mutation, independently checks required equivalence certificates through the minimal kernel, evaluates required invariants and the selected security profile, and runs optional tests with argv and `shell=False`. Raw string test commands are refused. Approval requires every selected check; application is atomic.
- Invariant callbacks receive `(before_path, after_path)` and must return `True` or evidence with `verdict: "proved"` to preserve an invariant. False, REFUTED, UNKNOWN, malformed results, and exceptions deny an edit that requires the invariant.
- `EditAudit` stores `original.txt`, `proposed.txt`, `change.diff`, `attempt.json`, and `decision.json` for every proposed patch, including rejected attempts. `EditAudit.verify()` checks artifact hashes and patch integrity.
- `repair_and_recheck()` returns `pegrex.repair-recheck.v1`. Its generator returns complete replacement source or `None`. Every candidate is reanalyzed in staging by the same analyzer; the target rule count must decrease and no other finding identity may increase. Rejection feedback is supplied to the next round and the real target remains unchanged until the patch gate approves. The additive `candidate_validator=` callback can require additional staged evidence without changing the legacy call shape.
- `sandboxed_differential()` returns `pegrex.sandboxed-differential.v1`. It runs the same argv-only harness against before/after source in separate ephemeral sandboxes. Matching return codes and bounded output produce `status: "passed"`, but `verdict` remains `unknown` because testing is not equivalence proof. Confirmed different observations are REFUTED; unavailable execution is UNKNOWN.
- `repair_with_sandboxed_differential()` returns `pegrex.agent-repair-differential.v1`. It requires sandbox availability, staged differential success, ordinary repair/policy approval, and an independent checker distinct from the generator. The checker must return `True` or `verdict: "proved"`; it is repeated after application. Post-fix UNKNOWN/REFUTED evidence or unexpected target bytes restore the original source and return `applied: false` with rollback evidence. Accepted/rejected patch-gate attempts remain durable.

## Multi-agent roles

`run_multi_agent_change()` returns `pegrex.multi-agent-change.v1`, with ordered `pegrex.agent-role-evidence.v1` records for candidate generation, patch generation, counterexample search, and independent checking. Candidate and patch callbacks are distinct stages; an independent checker may not be either generator callable. The default checker independently rechecks a canonical certificate through the minimal kernel. The role result is supplied to `apply_patch_gated()` as a candidate check and cannot itself authorize a write.

## Repository memory, graph, and change planning

- `RepositoryMemory.refresh()` produces `pegrex.repository-memory.v1` with content-defined API and memory identities, contracts, invariant references, dependencies, architectural boundary violations, and limitations. `query_api(function)` returns matching API summaries; `save()` and `load()` persist the normalized configuration and payload.
- `SemanticDependencyGraph.refresh()` returns the graph revision, changed nodes, reverse impacted nodes, counts, and UNKNOWN limitations. `payload()` uses `pegrex.semantic-dependency-graph.v1`. `dependencies(node)` walks forward edges and `impact(node)` walks reverse edges; unknown nodes return empty traversals rather than invented dependencies.
- Graph node kinds are `module`, `function`, `contract`, and `invariant`; edges include `contains`, `defines`, `witnesses`, `calls`, and `imports`. Conservative call resolution remains labeled in edge metadata.
- `plan_changes(graph, candidates)` returns `pegrex.risk-aware-change-plan.v1`. Ranked rows combine declared benefit, reachable impact, uncertainty, and proof effort. Missing targets, absent benefit, uncertainty outside `[0,1]`, and nonpositive/nonfinite proof effort remain unranked UNKNOWN rows after ranked candidates. A plan is prioritization evidence, not a proof or edit approval.

## Path, witness, replay, and compiler evidence

- `refine_paths()` returns `pegrex.path-refinement.v1`. `removed` retains infeasibility or dominance evidence, the removed path, and its dominator where applicable. UNKNOWN feasibility/subsumption never removes a path.
- `minimize_symbolic_witness()` returns `pegrex.counterexample-minimization.v1`. Every accepted shrink preserves the supplied constraints and optional reproducer. An invalid original witness or reproducer failure is UNKNOWN and unconfirmed.
- `mutation_controls()` / `standard_negative_controls()` return `pegrex.analyzer-mutation.v1`. Built-in controls deliberately weaken parsing, infeasibility solving, and command-flow rules. Baseline failure is UNKNOWN; a surviving weakened control is REFUTED.
- `export_smtlib()` returns `pegrex.smtlib-export.v1` with deterministic QF_LIA text, symbol mappings, and SHA-256 identity. Export requires no solver. `crosscheck_smtlib()` optionally uses Z3 and reports `sat`, `unsat`, or `unknown`.
- `replay_certificate()` returns `pegrex.proof-replay.v1`. The standalone `python pegrex/proofreplay.py CERTIFICATE` path uses only standard-library JSON/SHA-256, checks canonical equality and optional source hashes, and reports `solver_used: false`.
- `check_state_machine()` returns `pegrex.protocol-model-check.v1` with transitions/invariants, concrete violation traces, bounds, and exhausted/unknown status.
- `analyze_resource_bounds()` returns `pegrex.resource-bounds.v1` for termination, allocation sites, and worst-case asymptotic cost in its documented restricted fragment. Unsupported loops, recursion, and dynamic allocation remain UNKNOWN.
- `verify_compiler_change()` returns `pegrex.compiler-differential.v1` with exact source/artifact hashes and three-valued semantic evidence for compiler-produced Python artifacts.

## Security contracts and framework provenance

- `framework_packs()` returns `pegrex.taint-framework-packs.v1`; `analyze_with_frameworks()` adds selected pack provenance to the common flow report. Unknown pack names remain UNKNOWN.
- `SecurityContract` and `check_security_contract()` return `pegrex.security-contract.v1`. A matching unsanitized static flow refutes the property; absence is PROVED only within declared packs and a stable, complete fixed point. Required transformations are explicit sanitizer patterns.
- Flow findings now include `rule`, `rule_pack`, `matched_ast`, `flow_path`, `path_kind`, and `evidence_strength`. `static-source-to-sink` is static evidence, not a claim of runtime exploitation; `possible-flow` remains UNKNOWN.
- Secret sources include configuration/environment reads. HTTP sinks inspect URL and payload arguments, alongside log, telemetry, process, and other network sinks.

## Reachability, SBOM, lockfile policy, and build provenance

- `scan_reachable()` returns `pegrex.reachability-sca.v1` and embeds the original `pegrex.osv-scan.v1`. Each vulnerability remains `installed: true` and separately has `reachability: reachable|not-observed|unknown`. Reachable status requires a declared vulnerable symbol and a reachable static call. Missing symbols, parser gaps, and OSV gaps remain UNKNOWN.
- `generate_sbom()` returns CycloneDX 1.5 or SPDX 2.3 for `package-lock.json` and `Cargo.lock`. Documents include available package hashes, dependency relationships, license declarations, and lockfile provenance. Missing hashes/licenses are not invented.
- `check_lockfile_policy()` returns `pegrex.lockfile-policy.v1`. Exact-version, URL, VCS, and integrity violations REFUTE the selected policy. Typo-similarity produces a separate review signal and UNKNOWN when no harder violation exists.
- `create_build_provenance()` emits in-toto Statement v1 plus SLSA provenance v1 with subject/material SHA-256 digests and argv-only build commands. `verify_build_provenance()` recomputes supplied paths; mismatch is REFUTED and unavailable evidence is UNKNOWN. Unsigned local statements do not authenticate builder identity or hermeticity.

## IaC, attack paths, and exploitability evidence

- `analyze_iac()` covers IAM/Kubernetes JSON or YAML, Helm static YAML structure, Terraform and Dockerfile subsets, and NetworkPolicy world CIDRs. `coverage` includes parser identity, parser-specific confidence, and template-evaluation status. Helm templates are not evaluated; their presence and parse failures are UNKNOWN. Findings inherit parser confidence.
- `build_attack_graph()` and `AttackPathGraph.paths()` use `pegrex.attack-path-graph.v1`. Nodes/edges connect assets, identities, exposed services, dependencies, code sources, and sinks/reachable vulnerabilities. `complete: false` is UNKNOWN with `paths: []`; no capped partial path set is presented as complete.
- `assess_exploitability()` returns `pegrex.exploitability-evidence.v1`. Levels are exactly `pattern-match`, `confirmed-test`, `symbolic-witness`, and `sandboxed-reproduction`. Only confirmed evidence counts; sandbox reproduction additionally requires ephemeral isolation, no credentials, and no network. Missing rungs stay explicit and the level is not a probability or exploit guarantee.
- `run_poc()` returns `pegrex.poc-execution.v1`. It requires argv and bubblewrap/prlimit, uses only declared files in an ephemeral namespace, clears the environment, disables network, and applies resource limits. Missing isolation, setup failure, or unsafe files are UNKNOWN with no successful PoC claim. A nonzero payload result is not itself a reproduced PoC.

## Harness mutations and persistent security regressions

- `run_harness_policy_suite()` returns `pegrex.harness-policy-tests.v1` alongside the mutation report. The canonical `git status` argv must be allowed. Raw shell, chaining, quoted metacharacters, expansion, absolute paths, and Unicode confusables must remain refused under an allow-all mutation; launcher and `git push` policy mutations must be detected. Expectation mismatches are REFUTED and baseline/execution gaps are UNKNOWN.
- `register_finding_fix()` returns `pegrex.security-regression-memory.v1`. Registration requires the exact original rule to fire and the fixed source to be clear of that rule. The generated pytest contains both the fixed-finding regression and original-source negative control. `verify_regression_memory()` detects changed or missing generated tests; it does not claim that a missing rule proves all behavior safe.

## Context compilation and A2A tasks

- `compile_agent_context()` returns `pegrex.agent-context.v1`. It retains whole symbol, contract, invariant, dependency, test, and architecture records under a character budget. UNKNOWN markers are mandatory; inability to retain them or the envelope returns UNKNOWN with empty context. Lower-priority dropped records make a successful result `partial` and remain disclosed.
- `execute_task()` and `A2ATaskProtocol` use `pegrex.a2a-task.v1`. Handlers receive `(params, budget, deadline, cancel_event)` and must return an `evidence` field. Statuses are `completed`, `partial`, `cancelled`, `timeout`, and `unknown`. Cancellation is cooperative, late results preserve partial evidence, and `execution_active` reveals that a timed-out Python thread may still be running. JSON-RPC-shaped methods are `task.submit`, `task.cancel`, `task.status`, and `task.result`.

## Generated specifications and decision provenance

- `propose_spec()` returns `pegrex.spec-proposal.v1` with `status: "conjecture"` and `verdict: "unknown"`. `evaluate_proposal()` requires proof evidence for PROVED and a confirmed counterexample for REFUTED; checker errors, missing evidence, and unsupported values remain UNKNOWN. Generator metadata never evaluates the proposal.
- `explain_decision()` and `DecisionLog` use `pegrex.decision-provenance.v1`. Records include every rule constraint and match result, normalized action data, and allow/refuse/default-deny reason. Each JSONL record carries `previous_sha256` and `record_sha256`; `verify()` recomputes the chain and reports tampering rather than accepting the log's claims.

## Modernization and old/new API round trips

- `modernize_preserving_contracts()` returns `pegrex.contract-modernization.v1`. It independently reanalyzes emitted Python/Rust/Go and separates contract, numeric/overflow, and data-layout evidence. Overall PROVED requires all three layers within their declared scopes. Missing numeric/layout evidence is UNKNOWN; overlapping layout records are REFUTED; nonempty source layouts are not assumed to have compatible target lowering.
- `generate_api_stubs()` deterministically emits Python-server and Go-client stubs. `check_round_trip()` returns `pegrex.api-round-trip.v1`, separates static old/new OpenAPI drift from runtime cases, and requires every operation to have matching old/new observations for PROVED. Static agreement alone is UNKNOWN; confirmed mismatches are REFUTED; invoker failures and missing operations are UNKNOWN.

## Smart contracts, strict protocols, compiler IR, and prover exports

- `analyze_smart_contract()` returns `pegrex.smart-contract-evidence.v1` with independent `source`, `bytecode`, `formal`, and `local_evm` sections. Source checks are heuristic; bytecode parsing skips PUSH immediates; formal PROVED requires proof evidence and REFUTED requires a confirmed counterexample; local tests require confirmed local execution. Missing sections/runners remain UNKNOWN.
- `parse_protocol()` returns `pegrex.formal-protocol.v1` for `json`, `url`, `csv`, `ini`, `sexp`, and `properties`. It rejects duplicates, malformed syntax/escapes, inconsistent CSV widths, and trailing S-expression input. PROVED covers only well-formedness and the supported declarative schema subset, not application safety.
- `parse_compiler_ir()` returns `pegrex.compiler-ir.v1` for registered LLVM 17/18, MIR `rust-1`, and MLIR `1` grammars. Edges are derived only from parsed terminators. Unsupported terminators/versions and incomplete graphs are UNKNOWN even in proof mode; PROVED is limited to parsed CFG structure.
- `export_prover()` returns `pegrex.prover-bridge.v1` for `why3`, `smtlib`, `lean`, and `coq`, initially `unknown` / `not-checked`. Lean/Coq exports visibly contain `sorry`/`Admitted`. `check_prover_export()` changes the verdict only with explicit external proof or confirmed-counterexample evidence.

## Compliance packs and repository digital twins

- `create_compliance_pack()` returns `pegrex.compliance-evidence-pack.v1`. Executable flow contracts can be proved within analyzer scope; source observations and organizational/legal/procedural/runtime controls remain UNKNOWN when source cannot prove operational effectiveness. `legal_conclusion` is always null and the pack is not legal advice, certification, attestation, or a compliance conclusion.
- `build_repository_twin()` returns `pegrex.repository-digital-twin.v1` with a deterministic `twin_identity`, call and ownership data, contract/dependency graph, supplied history, and declared risk exposure. `twin_function_risk()` separates function callers in `impact` from all reverse nodes in `dependency_impact`; missing history and memory limitations remain visible.
- `detect_architecture_drift()` returns `pegrex.architecture-drift.v1` with `unintended-import` and `unintended-call-coupling` findings. Confirmed drift is REFUTED; absent findings do not erase incomplete repository evidence.

## Incident replay and trace-guided symbolic paths

- `replay_incident()` returns `pegrex.incident-replay.v1`, mapping trace events to `feasible-with-trace`, `unknown-feasibility`, or `infeasible-with-trace` contract paths. Patch candidates are analyzed and reported but never applied. Observed traces do not exclude unseen paths.
- `prioritize_symbolic_paths()` returns `pegrex.trace-guided-paths.v1`. Exact path IDs mark observations; compatible constraints alone produce `possibly-observed`. Feasible unseen/high-risk paths are prioritized, proved-infeasible paths receive zero priority, and unseen paths remain present. Exceeding `max_paths` returns UNKNOWN with no partial prioritized list.

## Proof-carrying releases and continuous assurance graphs

- `create_proof_carrying_release()` returns `pegrex.proof-carrying-release.v1` with verified source-contract identities, CycloneDX SBOM evidence, build attestation/verification, previous-release semantic diff, and a `pegrex.release-unknown-summary.v1`. `verify_release_pack()` rechecks the release identity and available upstream memory, lockfile, subjects/materials, and semantic evidence. Unsigned builder authentication/hermeticity remains UNKNOWN.
- `build_assurance_graph()` returns `pegrex.continuous-assurance-graph.v1`. Claim kinds are `api-contract`, `access-policy`, `taint-invariant`, and `migration-property`. Evidence edges include evidence and exact upstream identities. `invalidate_assurance()` preserves unchanged hashes and turns stale dependent PROVED claims into UNKNOWN; malformed/tampered graphs fail closed. `query_assurance()` returns no-match UNKNOWN rather than clean assurance.
- `summarize_semantic_change()` returns `pegrex.semantic-change-budget.v1` with public contracts, security findings, dependency-file identities, per-function cognitive deltas, and UNKNOWN regions. Nonnegative integer limits produce structured `budget_exceeded` rows. PROVED describes completeness within analyzer scope, not merge safety.

## Executable compliance maps and semantic checksums

- `build_compliance_map()` returns `pegrex.executable-compliance-map.v1`; `query_compliance_map()` returns bounded nodes/edges or UNKNOWN with no partial result. Classifications join source/sink traces, retention/deletion mappings, and infrastructure controls. Lifecycle operational effectiveness is not source-proved. Legal interpretation is human-required/reviewed and always `proved_by_code: false`.
- `semantic_checksum()` returns `pegrex.semantic-checksum.v1`, canonical serialization, normalized contracts, explicit type/domain assumptions, and location-independent effects. `diff_semantic_checksums()` reports changed components and treats mismatches without confirmed semantic evidence as UNKNOWN. `semantic_checksum_diff()` adds `explain_patch()` proof/counterexample evidence. Payload/hash tampering is REFUTED.
- `create_research_capsule()` emits deterministic `pegrex.security-research-capsule.v1` ZIP evidence with minimized/fixed source, preconditions, argv-only sandbox recipe, regression and negative controls, and proof/witness records. `verify_research_capsule()` checks paths, manifest identity, artifact hashes, fixed/vulnerable controls, and recipe confinement. It does not execute the recipe; unconfirmed minimization/proof remains UNKNOWN.

## Change-impact simulation and action broker

- `simulate_change_impact()` returns `pegrex.change-impact-simulation.v1` with `applied: false`. Proposed files are written only to a staged copy. Results cover contracts, policies, generated clients, data flows, and downstream modules/functions; possible invalidation is not merge authorization and client drift still needs runtime evidence.
- `create_action_plan()`, `authorize_action_plan()`, and `execute_action_plan()` implement separate plan, authorization, and execution schemas. Authorization binds exact plan/policy/workspace and must remain issued and unrevoked. Execution is ephemeral and argv-only for shell actions. `ActionEvidenceRecorder` hash-chains actual action records; direct file hashes and sandbox network evidence are explicit, unenumerated shell filesystem effects are UNKNOWN, and `authenticated: false` distinguishes local integrity from a signed attestation. `verify_action_evidence()` detects record or envelope tampering.
