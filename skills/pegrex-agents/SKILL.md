---
name: pegrex-agents
description: Integrate pegrex with AI agents via its three protocols (JSON-lines service, ACP, MCP with router). Use when building agent tooling or connecting an IDE.
---

# agent integration

## Protocols
- JSON-lines: `python service.py` — methods: parse, contracts, gaps, fix,
  verify, callgraph. One JSON object per line on stdio.
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

