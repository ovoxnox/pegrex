"""
lsp — language server protocol endpoint

║  Minimal stdio LSP: initialize handshake + textDocument/hover carrying  
║  the path contracts of the function under the cursor, plus              
║  textDocument/codeLens (per top-level def: path counts with proved /    
║  unknown split — opaque, non-linear constraints are reported unknown,   
║  never faked as proved) and the pegrex/showContracts executeCommand.    
║  Malformed protocol messages get JSON-RPC errors -- refused, never      
║  crashed. Results are cached per document version."""

from __future__ import annotations

import json
import re

from .sessions import AnalysisSession

_FUN_RX = re.compile(r"^def\s+([A-Za-z_]\w*)\s*\(([^)]*)\):", re.M)


def _contracts_for(source, fn_name, doc=None):
    session = (_DOCS.get(doc, {}).get("session") if doc is not None else None)
    if session is None or session.source != source:
        session = AnalysisSession(source)
    return [f"{' ∧ '.join(sorted(map(str, cs))) or 'true'} → {res}"
            for cs, res in session.contracts(fn_name)]


def _fn_at(source, line):
    """Function defined at/above 0-based line containing it."""
    lines = source.splitlines()
    best = None
    for i, l in enumerate(lines[: line + 1]):
        m = _FUN_RX.match(l)
        if m:
            best = (m.group(1), i)
    return best


def _defs(source):
    """Top-level def blocks: (name, 0-based def line, block text).

    A def block runs from its header to the next non-blank line at an
    indent <= the def's own (i.e. dedented out of the function)."""
    lines = source.splitlines()
    out = []
    i = 0
    while i < len(lines):
        m = _FUN_RX.match(lines[i])
        if not m:i += 1;continue
        indent = len(lines[i]) - len(lines[i].lstrip())
        j = i + 1
        while j < len(lines):
            l = lines[j]
            if l.strip() and (len(l) - len(l.lstrip())) <= indent:break
            j += 1
        out.append((m.group(1), i, "\n".join(lines[i:j]) + "\n"))
        i = j
    return out


def _status_rows(rows):
    """Count proved paths; opaque/non-linear constraints remain UNKNOWN."""
    from .linsolve import parse_atom
    from .refine import _norm_constraint
    proved, lines = 0, []
    for cs, res in rows:
        lines.append(f"{' ∧ '.join(sorted(map(str, cs))) or 'true'} → {res}")
        ok = True
        for c in cs:
            try:
                parse_atom(_norm_constraint(str(c)))
            except Exception:
                ok = False
                break
        proved += ok
    return len(rows), proved, lines


def _status(block):
    """Compatibility helper for one isolated function block."""
    return _status_rows(AnalysisSession(block).contracts())


def _lenses(doc, version, source):
    """One CodeLens per top-level def, cached by content digest."""
    hit = _CLCACHE.get(doc)
    session = _DOCS.get(doc, {}).get("session")
    if session is None or session.source != source:
        session = AnalysisSession(source)
        _DOCS.setdefault(doc, {})["session"] = session
    if hit and hit["source_sha256"] == session.digest:
        return hit["lenses"]
    lenses = []
    for name, line, block in _defs(source):
        try:
            n, proved, _ = _status_rows(session.contracts(name))
            unknown = n - proved
            title = f"pegrex: {n} paths · {proved} proved / {unknown} unknown"
        except Exception as e:  # engine refusal: loud, not a fake
            title = f"pegrex: unknown ({type(e).__name__})"
        lenses.append({
            "range": {"start": {"line": line, "character": 0},
                      "end": {"line": line,
                              "character": len(source.splitlines()[line])}},
            "command": {"title": title, "command": "pegrex.showContracts",
                        "arguments": [doc, name]}})
    _CLCACHE[doc] = {"source_sha256": session.digest, "lenses": lenses}
    return lenses


def _ok(mid, result=None) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _err(mid, code, message) -> dict:
    return {"jsonrpc": "2.0", "id": mid,
            "error": {"code": code, "message": message}}


def _uri(params):
    return params["textDocument"]["uri"]


def _h_initialize(mid, _params):
    return _ok(mid, {"capabilities": {
        "hoverProvider": True,
        "codeLensProvider": {"resolveProvider": False},
        "executeCommandProvider": {"commands": ["pegrex.showContracts"]},
        "textDocumentSync": 1}})


def _h_hover(mid, params):
    try:
        doc, line = _uri(params), params["position"]["line"]
    except (KeyError, TypeError):
        return _err(mid, -32602, "bad hover params")
    source = _DOCS.get(doc, {}).get("text", "")
    hit = _fn_at(source, line)
    if hit is None:
        return _ok(mid)
    contracts = _contracts_for(source, hit[0], doc)
    if not contracts:
        return _ok(mid)
    md = f"**path contracts: {hit[0]}**\n\n" + "\n\n".join(
        f"- `{c}`" for c in contracts)
    return _ok(mid, {"contents": {"kind": "markdown", "value": md}})


def _h_code_lens(mid, params):
    try:
        doc = _uri(params)
    except (KeyError, TypeError):
        return _err(mid, -32602, "bad codeLens params")
    entry = _DOCS.get(doc)
    if entry is None:
        return _ok(mid, [])
    try:
        return _ok(mid, _lenses(doc, entry.get("version"), entry["text"]))
    except Exception as e:
        return _err(mid, -32603, f"codeLens analysis refused: {e!r}")


def _h_execute(mid, params):
    if params.get("command") != "pegrex.showContracts":
        return _err(mid, -32601,
                    f"unsupported command {params.get('command')!r}")
    args = params.get("arguments") or []
    try:
        doc, fn = args[0], args[1]
        source = _DOCS[doc]["text"]
    except (IndexError, KeyError, TypeError):
        return _err(mid, -32602, "pegrex.showContracts needs "
                                 "[uri, functionName]")
    block = next((b for n, _, b in _defs(source) if n == fn), None)
    if block is None:
        return _err(mid, -32602, f"no such function {fn!r} in {doc}")
    try:
        session = _DOCS[doc].get("session")
        if session is None or session.source != source:
            session = AnalysisSession(source)
            _DOCS[doc]["session"] = session
        _, _, lines = _status_rows(session.contracts(fn))
    except Exception as e:
        return _err(mid, -32603, f"contract analysis refused: {e!r}")
    return _ok(mid, f"contracts: {fn}\n" + "\n".join(lines))


def _update_doc(uri, text, version):
    previous = _DOCS.get(uri, {})
    session = previous.get("session")
    if session is None or session.source != text:
        session = AnalysisSession(text, path=uri)
    _DOCS[uri] = {"text": text, "version": version, "session": session}
    _CLCACHE.pop(uri, None)


def _h_did_open(mid, params):
    try:
        td = params["textDocument"]
        _update_doc(td["uri"], td["text"], td.get("version"))
        return _ok(mid)
    except (KeyError, TypeError):
        return _err(mid, -32602, "bad didOpen params")


def _h_did_change(mid, params):
    try:
        doc = _uri(params)
        _update_doc(doc, params["contentChanges"][-1]["text"],
                    params["textDocument"].get("version"))
        return _ok(mid)
    except (KeyError, TypeError, IndexError):
        return _err(mid, -32602, "bad didChange params")


def _h_did_close(mid, params):
    try:
        doc = _uri(params)
        _DOCS.pop(doc, None)
        _CLCACHE.pop(doc, None)
        return _ok(mid)
    except (KeyError, TypeError):
        return _err(mid, -32602, "bad didClose params")


_HANDLERS = {
    "initialize": _h_initialize,
    "textDocument/hover": _h_hover,
    "textDocument/codeLens": _h_code_lens,
    "workspace/executeCommand": _h_execute,
    "textDocument/didOpen": _h_did_open,
    "textDocument/didChange": _h_did_change,
    "textDocument/didClose": _h_did_close,
}


def handle(message) -> dict:
    """One LSP/JSON-RPC message -> one response. Never raises."""
    if not isinstance(message, dict):
        return _err(None, -32600, "invalid request")
    mid, method = message.get("id"), message.get("method")
    fn = _HANDLERS.get(method)
    if fn is not None:
        try:
            return fn(mid, message.get("params") or {})
        except Exception as e:                    # a handler must never raise
            return _err(mid, -32603, f"{method} failed: {e!r}")
    if method in ("shutdown", "exit"):
        return _ok(mid)
    return _err(mid, -32601, f"unsupported method {method!r}")


_DOCS = {}
_CLCACHE = {}


def serve(stream_in, stream_out) -> None:
    """stdio LSP with Content-Length framing (via wire)."""
    from .wire import serve_lsp
    serve_lsp(handle, stream_in, stream_out)
