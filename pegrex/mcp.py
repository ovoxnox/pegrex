"""
mcp -- Model Context Protocol server + Proxy/Router 

║  The engine's tools exposed as MCP tools (tools/list, tools/call,        
║  resources for catalogs).  MCPProxy routes tool calls by prefix:         
║  'engine.*' stays local; anything else forwards to registered            
║  upstream MCP servers (JSON-RPC stdio), making pegrex a transparent      
║  aggregation layer over multiple tool providers."""

from __future__ import annotations

import json
import subprocess
import sys

PROTOCOL_VERSION = "2026-11-05"


def engine_tools() -> list:
    """MCP tool descriptors over the Core Tools Engine."""
    return [
        {"name": "engine_audit", "description":
         "Security audit (patterns + taint + SCA) on a source file",
         "inputSchema": {"type": "object",
                         "properties": {"path": {"type": "string"}},
                         "required": ["path"]}},
        {"name": "engine_contracts", "description":
         "Function contract (constraints -> results)",
         "inputSchema": {"type": "object",
                         "properties": {"path": {"type": "string"},
                                        "language": {"type": "string"}},
                         "required": ["path"]}},
        {"name": "engine_callgraph", "description":
         "Function-call graph (DOT + ASCII)",
         "inputSchema": {"type": "object",
                         "properties": {"source": {"type": "string"}},
                         "required": ["source"]}},
        {"name": "engine_spec", "description":
         "Generate AI spec schema (multi-view)",
         "inputSchema": {"type": "object",
                         "properties": {"source": {"type": "string"},
                                        "name": {"type": "string"}},
                         "required": ["source", "name"]}},
        {"name": "engine_gaps", "description":
         "Coverage gaps with constraint context",
         "inputSchema": {"type": "object",
                         "properties": {"source": {"type": "string"},
                                        "lcov": {"type": "string"}},
                         "required": ["source", "lcov"]}},
        {"name": "engine_search", "description":
         "RAG retrieval over indexed sources",
         "inputSchema": {"type": "object",
                         "properties": {"query": {"type": "string"}},
                         "required": ["query"]}},
    ]


def call_engine_tool(name: str, args: dict):
    sys.path.insert(0, ".")
    from pegrex import api
    if name == "engine_audit":
        return api.audit(args["path"])
    if name == "engine_contracts":
        return api.contracts(args["path"], args.get("language", "python"))
    if name == "engine_callgraph":
        g = api.call_graph(args["source"])
        return {"ascii": g.to_ascii(), "edges": sorted(list(g.edges))}
    if name == "engine_spec":
        import tempfile
        return api.spec(args["source"], args["name"],
                        out_dir=tempfile.mkdtemp())
    if name == "engine_gaps":
        return api.gaps(args["source"], args["lcov"])
    if name == "engine_search":
        idx = getattr(api, "_rag", None) or api.rag_index(["."])
        api._rag = idx
        return [{"source": h.source, "line": h.start_line}
                for h in api.rag_search(idx, args["query"])]
    raise ValueError(f"unknown tool {name!r}")


class MCPRouter:
    """Routes MCP tool calls: local engine.* or by-prefix to upstream
    MCP servers spawned as subprocesses (stdio JSON-RPC)."""

    def __init__(self) -> None:
        """  init  (): see module docstring."""
        self.upstreams: dict[str, subprocess.Popen] = {}

    def register(self, prefix: str, command: list[str]) -> None:
        """prefix -> spawn an upstream MCP server for that namespace."""
        proc = subprocess.Popen(command, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, text=True)
        self.upstreams[prefix] = proc
        self._rpc(proc, "initialize",
                  {"protocolVersion": PROTOCOL_VERSION,
                   "capabilities": {}, "clientInfo": {"name": "pegrex-router"}})

    def _rpc(self, proc, method, params, rid=1):
        req = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        proc.stdin.write(json.dumps(req) + chr(10))
        proc.stdin.flush()
        return json.loads(proc.stdout.readline())

    def route(self, tool: str, arguments: dict):
        """Dispatch by longest matching prefix."""
        best, proc = None, None
        for prefix, p in self.upstreams.items():
            if tool.startswith(prefix) and (best is None
                                            or len(prefix) > len(best)):
                best, proc = prefix, p
        if proc is None:
            return call_engine_tool(tool, arguments)
        return self._rpc(proc, "tools/call",
                         {"name": tool, "arguments": arguments}).get("result")

    def close(self) -> None:
        """close(): see module docstring."""
        for p in self.upstreams.values():
            p.terminate()


class MCPServer:
    """MCP server: the engine behind an MCP-compatible stdio transport."""

    def __init__(self, router: MCPRouter | None = None) -> None:
        """  init  (router): see module docstring."""
        self.router = router or MCPRouter()

    def handle(self, req: dict):
        m = req.get("method")
        if m == "initialize":
            return {"protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "pegrex", "version": "1.0.0"}}
        if m == "notifications/initialized":
            return None
        if m == "tools/list":
            return {"tools": engine_tools()}
        if m == "tools/call":
            p = req.get("params", {})
            out = self.router.route(p["name"], p.get("arguments", {}))
            return {"content": [{"type": "text",
                                 "text": json.dumps(out, default=str)[:4000]}]}
        if m == "resources/list":
            return {"resources": [
                {"uri": "pegrex://rules", "name": "security rule catalog",
                 "mimeType": "application/json"},
                {"uri": "pegrex://taint-rules", "name": "taint rule pack",
                 "mimeType": "application/json"}]}
        if m == "resources/read":
            uri = req.get("params", {}).get("uri", "")
            import pathlib
            f = pathlib.Path("pegrex/secrules.json")
            if "taint" in uri:
                f = pathlib.Path("pegrex/secrules_taint.json")
            return {"contents": [{"uri": uri, "mimeType": "application/json",
                                  "text": f.read_text()[:8000]}]}
        return None

    def serve(self) -> int:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                req = json.loads(line)
                resp = self.handle(req)
            except Exception as e:
                resp = {"jsonrpc": "2.0",
                        "error": {"code": -32000, "message": repr(e)[:200]},
                        "id": req.get("id") if isinstance(req, dict) else None}
            if resp is not None and isinstance(resp, dict) \
                    and isinstance(req, dict) and "id" in req:
                out = dict(resp)
                out.setdefault("jsonrpc", "2.0")
                out["id"] = req.get("id")
                import sys as _sys; _sys.stdout.write(json.dumps(out) + chr(10)); _sys.stdout.flush()
        return 0


if __name__ == "__main__":
    raise SystemExit(MCPServer().serve())
