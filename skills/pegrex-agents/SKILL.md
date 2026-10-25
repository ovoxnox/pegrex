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
    api.synthesize(src, lcov) / api.transpile(src, lang) / api.verify_protocol(...)

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

