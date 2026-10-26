---
name: pegrex-agents
description: Integrate pegrex with AI agents via its three protocols (JSON-lines service, ACP, MCP with router). Use when building agent tooling or connecting an IDE.
---

# agent integration

## Protocols
- JSON-lines: `python service.py` — methods: parse, contracts, gaps, fix,
  verify, callgraph, soundness. One JSON object per line on stdio.
- Read `soundness` before choosing a frontend: it publishes parser versions,
  analysis coverage, maturity, and known unsupported cases from the canonical
  registry. Parsing support is not contract or proof support.
- ACP (Zed): `python pegrex.py acp` — session/prompt, 6 tools, RAG search.
- MCP: `python -m pegrex.mcp` — tools/list + tools/call, rule catalogs as
  resources.

## MCP Router (aggregation)
    from pegrex.mcp import MCPRouter, MCPServer
    router = MCPRouter()
    router.register("github", ["npx", "-y", "@modelcontextprotocol/server-github"])
    server = MCPServer(router)   # engine.* local, github.* proxied

## Prompt shortcuts (ACP)
    audit <file>      -> runs the auditor, returns finding summary
    search <query>    -> RAG-retrieved chunks from indexed sources

## Python API (simplest integration)
    from pegrex import api
    api.audit(path) / api.contracts(path) / api.spec(src, name) /
    api.coverage(path, lcov) / api.call_graph(src) / api.gaps(src, lcov) /
    api.synthesize_tests_from_coverage(src, lcov) / api.transpile(src, lang) /
    api.verify_protocol(...)

`api.synthesize` is program synthesis, not coverage-test synthesis. Candidate
transpilation is not verified until its independent certificate passes.

## Shared analysis and resource limits
- For multiple analyses of one source, use `AnalysisSession`: its normalized
  tree is shared by contracts, call graph, complexity, security, test synthesis,
  and LSP documents. Persistent identities use content + versions + configuration.
- Treat path caps, per-file deadlines, and solver budget exhaustion as UNKNOWN.
  Use `PathEnumerator.enumerate_bounded()` or `LinearBackend.entails_with_status()`
  when the caller must observe incomplete analysis; never consume partial paths
  as proof. Directory call-graph multiprocessing is opt-in with `--jobs`; measure
  small-repository overhead with `--benchmark`.

## Security integration
- Agent shell plans must contain argv, for example
  `{"tool":"shell","argv":["git","status"]}`. Never substitute a raw command
  string; the harness refuses it along with expansion, chaining, launchers,
  absolute/traversal/symlink paths, and Unicode executable/path lookalikes.
- Use `audit FILE --sarif --out results.sarif` for GitHub Code Scanning. Preserve
  its source/rule/parser provenance, source/sink code flows, fingerprints, and
  suppression justifications. A suppression without `-- JUSTIFICATION` is invalid.
- For dependency scans, use `osvscan LOCKFILE --offline --osv-snapshot FILE`.
  Missing snapshot entries are UNKNOWN, not zero vulnerabilities.

## Typed evidence and separated change roles
- Use `pegrex.agenttools.query_contracts`, `verify_change`, and
  `find_counterexample` for versioned evidence envelopes and source provenance.
  Only `confirmed: true` counterexamples are refutations.
- Use `run_multi_agent_change` to separate candidate generation, patch generation,
  counterexample search, and independent checking. The checker cannot be a
  generator, and role evidence still passes through the proof gate before a write.
- Select UNKNOWN failures with `SecurityProfile`; explicit allowances stay
  visible in `accepted_unknowns` and never mean that missing evidence is clean.

## Budgeted context, tasks, and repair
- `compile_agent_context` retains symbols, contracts, invariants, dependencies,
  tests, and mandatory UNKNOWN markers under a character budget. Do not use a
  compressed context that had to discard mandatory uncertainty.
- `A2ATaskProtocol` exposes submit/cancel/status/result with budgets, deadlines,
  evidence, partial results, and cooperative cancellation. `execution_active`
  must remain visible after a timeout; never claim a Python thread was killed.
- Treat `propose_spec` output as a conjecture. `evaluate_proposal` needs proof or
  a confirmed counterexample; every other result is UNKNOWN.
- `repair_with_sandboxed_differential` requires isolated before/after tests,
  staged independent validation, the ordinary patch gate, and independent
  post-fix proof. Post-fix UNKNOWN restores the original; matching differential
  output alone is not semantic-equivalence proof.
- Use `DecisionLog` to retain the exact allow/refuse rules, normalized action,
  reasons, and hash-chain evidence for agent-plan decisions.

## Secure action brokerage
- Keep `create_action_plan`, `authorize_action_plan`, and `execute_action_plan`
  separate. Execution requires the exact plan/policy/workspace and an unrevoked
  authorization actually issued by the policy engine.
- Shell execution remains argv-only and ephemeral. Record actual argv, direct file
  hashes, and sandbox network evidence; shell filesystem effects are UNKNOWN when
  not enumerated. The evidence hash chain is not a signed attestation.
