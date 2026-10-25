#!/usr/bin/env python
"""pegrex service -- stdio JSON-lines server (the Rust/Go consumption seam).

Protocol: one JSON object per line on stdin; one JSON object per line on
stdout.  Methods:

  {"method": "ping"}
      -> {"ok": true, "pong": true}

  {"method": "parse", "params": {"language": "REGISTERED_ID", "source": "..."}}
      -> {"ok": true, "ast": {tag, pos, endpos, children: [...]}}

  {"method": "contracts", "params": {"language": "REGISTERED_ID", "source": "..."}}
      -> {"ok": true, "contract": [[[constraints...], result], ...]}

  {"method": "soundness", "params": {"language": "OPTIONAL_REGISTERED_ID"}}
      -> {"ok": true, "soundness": {schema, policy, plugins}}

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


def node_to_dict(node):
    if isinstance(node, Node):
        return {"tag": node.tag, "pos": node.pos, "endpos": node.endpos,
                "children": [node_to_dict(c) for c in node.children]}
    if isinstance(node, list):
        return [node_to_dict(c) for c in node]
    return node


from pegrex.core import get_engine

def handle(req):
    method = req.get("method")
    params = req.get("params", {})
    if method == "ping":
        return {"ok": True, "pong": True}
    if method == "soundness":
        result = get_engine().soundness(params.get("language"))
        return {"ok": True, "soundness": result.data}
    if method == "parse":
        result = get_engine().parse(params["source"], params["language"],
                                    function_body=True,
                                    entrypoint=params.get("entrypoint"))
        return {"ok": True, "ast": result.data["tree"],
                "language": result.data["language"], "node_count": result.data["node_count"]}
    if method == "contracts":
        result = get_engine().extract_contracts(params["source"], params["language"])
        return {"ok": True, "status": result.status.value,
                "contract": [[row["constraints"], row["outcome"]]
                             for row in (result.data or [])],
                "unknowns": result.unknowns, "metadata": result.metadata}
    if method == "callgraph":
        source_path = pathlib.Path(params["source"])
        if not source_path.is_absolute():
            source_path = ROOT / source_path
        src = source_path.read_text(encoding="utf-8")
        result = get_engine().call_graph(src, params.get("language", "python"))
        return {"ok": True, **result.to_dict(),
                "ascii": result.data["ascii"], "edges": result.data["edges"]}

    if method == "gaps":
        src = params["source"]
        lcov = params.get("lcov", "")
        language = params.get("language", "python")
        from pegrex.languages import get_contract_frontend
        from pegrex.cfg import CFGBuilder as _CB
        from pegrex.coverage import (parse_lcov, covered_lines, coverage_gaps)
        cov = list(parse_lcov(lcov).values())
        cov_lines = covered_lines(cov[0]) if cov else set()
        parse, tags, mk = get_contract_frontend(language)()
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
        return {"ok": True, "status": "completed", "verified": False,
                "certificate": None,
                "certificate_note": "Pipeline completed; no independently checkable proof object was emitted.",
                "log": buf.getvalue(),
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
