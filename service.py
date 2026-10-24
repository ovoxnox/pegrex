#!/usr/bin/env python
"""pegrex service -- stdio JSON-lines server (the Rust/Go consumption seam).

Protocol: one JSON object per line on stdin; one JSON object per line on
stdout.  Methods:

  {"method": "ping"}
      -> {"ok": true, "pong": true}

  {"method": "parse", "params": {"language": "lua|c", "source": "..."}}
      -> {"ok": true, "ast": {tag, pos, endpos, children: [...]}}

  {"method": "contracts", "params": {"language": "lua|c", "source": "..."}}
      -> {"ok": true, "contract": [[[constraints...], result], ...]}

  {"method": "verify", "params": {"spec": "specs/fact.json"}}
      -> {"ok": true, "certificate": true, "name": ...}

Any client (Rust, Go, anything) can drive the full pipeline over pipes.
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).parent
sys.path.insert(0, str(ROOT))

import pipeline
from pegrex.peg import Node
from pegrex.cfg import CFGBuilder
from pegrex.summaries import render_lua, render_c, path_summaries


def node_to_dict(node):
    if isinstance(node, Node):
        return {"tag": node.tag, "pos": node.pos, "endpos": node.endpos,
                "children": [node_to_dict(c) for c in node.children]}
    if isinstance(node, list):
        return [node_to_dict(c) for c in node]
    return node


_TS_LANGS = ("python", "go", "rust")


def _frontend(lang):
    if lang == "c":
        return pipeline.c_frontend()
    if lang in ("python", "go", "rust", "javascript", "solidity", "julia",
                "kotlin"):
        return {"python": pipeline.python_frontend,
                "go": pipeline.go_frontend,
                "rust": pipeline.rust_frontend,
                "javascript": pipeline.javascript_frontend,
                "solidity": pipeline.solidity_frontend,
                "julia": pipeline.julia_frontend,
                "kotlin": pipeline.kotlin_frontend}[lang]()
    return _ts_frontend(lang)


def _ts_frontend(lang):
    """Real tree-sitter frontend for Python/Go/Rust."""
    import tree_sitter_python, tree_sitter_go, tree_sitter_rust
    from tree_sitter import Language, Parser
    from pegrex.tree_sitter_bridge import ts_to_pegrex, TAGSPECS

    langs = {"python": Language(tree_sitter_python.language()),
             "go": Language(tree_sitter_go.language()),
             "rust": Language(tree_sitter_rust.language())}

    def parse(src):
        root = Parser(langs[lang]).parse(src.encode()).root_node
        return ts_to_pegrex(root, src)

    return parse, TAGSPECS[lang], None


def handle(req):
    method = req.get("method")
    params = req.get("params", {})
    if method == "ping":
        return {"ok": True, "pong": True}
    if method == "parse":
        parse, _, _ = _frontend(params["language"])
        return {"ok": True, "ast": node_to_dict(parse(params["source"]))}
    if method == "contracts":
        lang = params["language"]
        src = params["source"]
        parse, tagspec, make_cond = _frontend(lang)
        body = parse(src)
        if make_cond is None:
            return {"ok": False,
                    "error": "contracts not supported for this frontend"}
        if lang == "lua":
            render = lambda st: render_lua(st)
        elif lang == "c":
            render = lambda st: render_c(st, src)
        else:
            def render(st, _s=src):
                t = st.children[0] if st.children and \
                    isinstance(st.children[0], str) else _s[st.pos:st.endpos]
                return t.replace("return", "").strip()
        contract = path_summaries(CFGBuilder(tagspec).build(body),
                                  make_cond(src), render)
        return {"ok": True,
                "contract": [[sorted(c), r] for c, r in contract]}
    if method == "callgraph":
        from pegrex.callgraph import build_call_graph
        src = pathlib.Path(ROOT / params["source"]).read_text() \
            if not pathlib.Path(params["source"]).exists() else \
            pathlib.Path(params["source"]).read_text()
        g = build_call_graph(src, params.get("language", "python"))
        return {"ok": True,
                "ascii": g.to_ascii(),
                "edges": sorted(list(g.edges))}

    if method == "gaps":
        src = params["source"]
        lcov = params.get("lcov", "")
        import pipeline as _pl
        from pegrex.cfg import CFGBuilder as _CB
        from pegrex.coverage import (parse_lcov, covered_lines, coverage_gaps)
        cov = list(parse_lcov(lcov).values())
        cov_lines = covered_lines(cov[0]) if cov else set()
        parse, tags, mk = _pl.python_frontend()
        cfg = _CB(tags).build(parse(src))
        gaps = coverage_gaps(cfg, mk(src), cov_lines)
        return {"ok": True, "gaps": [
            {"constraints": g["constraints"],
             "suggestion": "add a test satisfying: "
                           + " and ".join(g["constraints"])}
            for g in gaps]}

    if method == "fix":
        # finding-local repair context: just the finding + its fix recipe
        src = params["source"]
        lang = params.get("language") or "python"
        from pegrex.api import audit
        from pegrex.wire import temp_source
        with temp_source(src) as tmp_path:
            findings = audit(tmp_path, lang)
        fid = params.get("finding_id")
        focused = [f for f in findings if not fid or f["id"] == fid]
        FIXES_HINT = {
            "R2-CMD-INJECTION": "whitelist-validate or address by validated offset",
            "DICT-ACCESS-UNGUARDED": "guard with .get() or pre-check membership",
        }
        hints = [{"id": f["id"], "line": f["line"], "evidence": f["evidence"],
                  "fix": FIXES_HINT.get(f["id"], f.get("message", "review"))}
                 for f in focused]
        return {"ok": True, "focus": hints,
                "context_window": "finding-local (not whole-file)"}

    if method == "verify":
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):       # keep protocol channel clean
            pipeline.run_spec(params["spec"])
        return {"ok": True, "certificate": True, "log": buf.getvalue(),
                "name": json.loads((ROOT / params["spec"]).read_text())["name"]}
    return {"ok": False, "error": f"unknown method {method!r}"}


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            resp = handle(json.loads(line))
        except Exception as e:
            resp = {"ok": False, "error": repr(e)}
        print(json.dumps(resp), flush=True)


if __name__ == "__main__":
    main()
