"""
acp

Agent Client Protocol server (Zed ACP-compatible, JSON-RPC 2.0 over stdio): 
  the engine's tools are the agent's tools. Prompts route to
    the core engine; RAG grounds retrieval prompts with indexed context.

Methods: initialize, authenticate, session/new, session/prompt,
           session/update (notification), tools/list, tools/call
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

PROTOCOL_VERSION = 1


class AcpServer:
    """ACP server: engine tools exposed as agent-callable tools."""

    def __init__(self, root=".") -> None:
        self.root = str(Path(root).resolve())
        self.sessions: dict[str, dict] = {}
        self._counter = 0
        self._rag = None

    def _resolve(self, path: str) -> str:
        """Resolve one workspace path without permitting traversal or symlink escape."""
        candidate = Path(path)
        if not candidate.is_absolute():
            candidate = Path(self.root) / candidate
        resolved = candidate.resolve()
        try:
            resolved.relative_to(self.root)
        except ValueError as error:
            raise ValueError(f"path escapes ACP workspace: {path!r}") from error
        return str(resolved)

    # ── tool definitions
    def tools(self) -> list[dict]:
        """tools(): see module docstring."""
        return [
            {"name": "engine.audit", "description":
             "security audit (patterns + taint + SCA) on a source file",
             "inputSchema": {"type": "object",
                             "properties": {"path": {"type": "string"}},
                             "required": ["path"]}},
            {"name": "engine.contracts", "description":
             "function contract (paths -> results) for a source file",
             "inputSchema": {"type": "object",
                             "properties": {"path": {"type": "string"},
                                            "language": {"type": "string"}},
                             "required": ["path"]}},
            {"name": "engine.spec", "description":
             "generate an AI spec schema (multi-view)",
             "inputSchema": {"type": "object",
                             "properties": {"source": {"type": "string"},
                                            "name": {"type": "string"}},
                             "required": ["source", "name"]}},
            {"name": "engine.gaps", "description":
             "coverage gaps with constraint context (source + lcov)",
             "inputSchema": {"type": "object",
                             "properties": {"source": {"type": "string"},
                                            "lcov": {"type": "string"}},
                             "required": ["source", "lcov"]}},
            {"name": "engine.tests", "description":
             "synthesize tests from coverage gaps",
             "inputSchema": {"type": "object",
                             "properties": {"source": {"type": "string"},
                                            "lcov": {"type": "string"}},
                             "required": ["source", "lcov"]}},
            {"name": "engine.search", "description":
             "RAG retrieval over indexed sources",
             "inputSchema": {"type": "object",
                             "properties": {"query": {"type": "string"},
                                            "k": {"type": "integer"}},
                             "required": ["query"]}},
        ]

    def _read(self, path: str) -> str:
        with open(self._resolve(path), encoding="utf-8", errors="replace") as fh:
            return fh.read()

    def call_tool(self, name: str, args: dict):
        """call tool(name, args): see module docstring."""
        if not isinstance(args, dict):
            raise TypeError("arguments must be an object")
        args = dict(args)
        for key in ("path", "source", "lcov"):
            if key in args:
                args[key] = self._resolve(str(args[key]))
        if name == "engine.audit":
            from tools.secaudit import audit
            return audit(args["path"])
        if name == "engine.contracts":
            import pipeline
            lang = args.get("language") or "python"
            src = self._read(args["path"])
            parse, tags, mk = pipeline.frontend_for(lang)
            body = parse(src)
            from pegrex.cfg import CFGBuilder
            from pegrex.summaries import path_summaries
            render = (lambda st: (src[st.pos:st.endpos])
                      .replace("return", "").strip())
            return [list(map(list, t)) for t in
                    path_summaries(CFGBuilder(tags).build(body), mk(src), render)]
        if name == "engine.gaps" or name == "engine.tests":
            import pipeline
            from pegrex.cfg import CFGBuilder
            from pegrex.coverage import (parse_lcov, covered_lines,
                                         coverage_gaps)
            src = self._read(args["source"])
            lcov = self._read(args["lcov"])
            cov = list(parse_lcov(lcov).values())
            cov_lines = covered_lines(cov[0]) if cov else set()
            parse, tags, mk = pipeline.python_frontend()
            cfg = CFGBuilder(tags).build(parse(src))
            if name == "engine.gaps":
                return [{"constraints": sorted(set(
                             c for c in g["constraints"]))}
                        for g in coverage_gaps(cfg, mk(src), cov_lines)]
            from pegrex.testsynth import synthesize_tests
            return [t.test_body for t in
                    synthesize_tests(cfg, mk(src), cov_lines,
                                     args["source"].split("/")[-1][:-3])]
        if name == "engine.search":
            from pegrex.rag import build_index, retrieve
            if self._rag is None:
                self._rag = build_index([self.root])
            hits = retrieve(self._rag, args["query"], args.get("k", 5))
            return [{"source": h.source, "line": h.start_line,
                       "text": h.text[:200]} for h in hits]
        raise ValueError(f"unknown tool {name!r}")

    # ── ACP protocol
    def handle(self, req: dict) -> dict | None:
        """handle(req): see module docstring."""
        method = req.get("method")
        params = req.get("params", {})
        rid = req.get("id")
        if method == "initialize":
            return {"protocolVersion": PROTOCOL_VERSION,
                    "agentCapabilities": {"loadSession": False,
                                          "promptCapabilities":
                                          {"image": False, "audio": False}}}
        if method == "authenticate":
            return {"method": "apiKey"}
        if method == "session/new":
            self._counter += 1
            sid = f"s{self._counter}"
            self.sessions[sid] = {}
            return {"sessionId": sid}
        if method == "session/prompt":
            sid = params["sessionId"]
            prompt = "".join(c.get("text", "")
                             for c in params.get("prompt", [])
                             if c.get("type") == "text")
            reply = self._prompt(sid, prompt)
            if rid is not None:
                return {"sessionId": sid, "result": reply}
            return None
        if method == "tools/list":
            return {"tools": self.tools()}
        if method == "tools/call":
            out = self.call_tool(params["name"], params.get("arguments", {}))
            return {"content": [{"type": "text",
                                 "text": json.dumps(out, default=str)[:2000]}]}
        return None

    def _prompt(self, sid: str, prompt: str) -> str:
        """Route a natural-language-ish prompt to the engine; 'search ...'
        queries go through RAG with grounded context."""
        low = prompt.lower().strip()
        if low.startswith("search "):
            hits = self.call_tool("engine.search", {"query": prompt[7:]})
            ctx = "\n\n".join(f"### {h['source']}:{h['line']}\n{h['text']}"
                                for h in hits[:3])
            return (f"Retrieved {len(hits)} chunk(s). Top context:\n\n{ctx}"
                    if hits else "No relevant chunks found.")
        if low.startswith("audit "):
            findings = self.call_tool("engine.audit", {"path": prompt[6:].strip()})
            return (f"{len(findings)} finding(s):\n"
                    + "\n".join(f"- {f['severity']} {f['id']} L{f['line']}"
                                 for f in findings[:10]))
        return ("pegrex engine ready. Try: 'audit <file>', "
                "'search <query>', or the tools/list + tools/call API.")


def main(root=".") -> int:
    """Implement main with the module's explicit API and failure semantics."""
    server = AcpServer(root)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        req = None
        try:
            req = json.loads(line)
            resp = server.handle(req)
        except Exception as e:
            resp = {"jsonrpc": "2.0",
                    "error": {"code": -32000, "message": repr(e)[:200]},
                    "id": req.get("id") if isinstance(req, dict) else None}
        if (resp is not None and isinstance(resp, dict)
                and (not isinstance(req, dict) or "id" in req)):
            out = dict(resp)
            out.setdefault("jsonrpc", "2.0")
            out["id"] = req.get("id") if isinstance(req, dict) else None
            print(json.dumps(out), flush=True)
    return 0


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")
