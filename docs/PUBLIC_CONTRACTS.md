# PegRex public contracts

This document characterizes the compatibility surface protected by `tests/test_public_contracts.py` and the existing API, service, CLI, and stable-architecture suites. It describes behavior, not a claim that every analyzer is complete.

## Versions and value domains

- Core serialized models carry `schema: "pegrex.core.v1"`; `CoreEngine.schema` is `"pegrex.core-engine.v1"`; the legacy capability matrix uses `"pegrex.language-capabilities.v1"`. Soundness reports use `"pegrex.soundness.v1"`.
- Verification verdicts are exactly `proved`, `refuted`, and `unknown`. A missing proof or unconfirmed witness is `unknown`, not `refuted` and never `proved`.
- Operation statuses are `ok`, `partial`, and `error`. Partial results explain incomplete coverage in `unknowns`.
- Source spans are zero-based, end-exclusive Python character offsets, including at adapter boundaries backed by Tree-sitter UTF-8 byte offsets.

## Stable core models

`SourceDocument.text`, `.language`, `.path`, and `.sha256` define an immutable source. Its `to_dict()` emits `schema`, `path`, `language`, `sha256`, `characters`, and `utf8_bytes`.

`PathContract` is an explicit `(constraints, outcome)` record with optional `function`, `source_hash`, and metadata. Identity includes outcome and the other identity fields; constraints are sorted and whitespace-normalized. `to_dict()` emits `schema`, `constraints`, `outcome`, `function`, `source_hash`, `metadata`, and `identity`.

`OperationResult.to_dict()` emits exactly `schema`, `operation`, `status`, `verdict`, `data`, `unknowns`, `assumptions`, and `metadata`. Contract rows in `CoreEngine.extract_contracts()` use the `PathContract` shape above.

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

`soundness_report()` and `CoreEngine.soundness()` return the `pegrex.soundness.v1` report. Its `policy` states verdict, coordinate, counterexample, scanner-coverage, and completion rules; `plugins` contains one or all canonical manifests. This is a capability and limitation report, not a runtime proof that optional parser dependencies are installed.

## Analysis limits

Taint is source-order and heuristic, with light interprocedural propagation; it is not CFG/SSA or field-sensitive proof. Strict unresolved flows remain `unknown`. Scanner input limits, rejected rules, parser gaps, match caps, and regex timeouts likewise produce unknown coverage findings rather than silent clean results.
