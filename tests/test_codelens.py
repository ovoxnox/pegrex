import json
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pegrex import api, lsp

ROOT = pathlib.Path(__file__).resolve().parent.parent

FIXTURE = (
    "def classify(n):\n"
    "    if n > 0:\n"
    "        return 1\n"
    "    return -1\n"
    "\n"
    "def mul(a, b):\n"
    "    if a * b > 0:\n"
    "        return 1\n"
    "    return 0\n"
)


def _open(uri, text, version=1):
    return lsp.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen",
                       "params": {"textDocument": {"uri": uri,
                                                   "languageId": "python",
                                                   "version": version,
                                                   "text": text}}})


def _lenses(uri):
    r = lsp.handle({"jsonrpc": "2.0", "id": 1, "method": "textDocument/codeLens",
                    "params": {"textDocument": {"uri": uri}}})
    assert "error" not in r, r
    return r["result"]


def test_initialize_advertises_codelens_and_execute_command():
    r = lsp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {}})
    caps = r["result"]["capabilities"]
    assert caps["hoverProvider"] is True
    assert caps["codeLensProvider"] == {"resolveProvider": False}
    assert caps["executeCommandProvider"]["commands"] == ["pegrex.showContracts"]


def test_codelens_per_def_with_engine_numbers(tmp_path):
    uri = "file:///test_codelens_numbers.py"
    _open(uri, FIXTURE)
    lenses = _lenses(uri)
    assert len(lenses) == 2
    titles = {l["command"]["arguments"][1]: l["command"]["title"]
              for l in lenses}
    assert "paths" in titles["classify"]
    # cross-check against a direct api.contracts call per function slice
    lines = FIXTURE.splitlines()
    for name, start, end in (("classify", 0, 4), ("mul", 5, 9)):
        p = tmp_path / f"{name}.py"
        p.write_text("\n".join(lines[start:end]) + "\n")
        expect = len(api.contracts(str(p)))
        got = int(titles[name].split("paths")[0].strip().split(":")[1])
        assert got == expect
    assert titles["classify"] == "pegrex: 2 paths · 2 proved / 0 unknown"
    assert titles["mul"] == "pegrex: 2 paths · 0 proved / 2 unknown"


def test_unknown_paths_never_faked_as_proved():
    uri = "file:///test_codelens_unknown.py"
    _open(uri, FIXTURE)
    titles = {l["command"]["arguments"][1]: l["command"]["title"]
              for l in _lenses(uri)}
    # non-linear constraints (a*b) cannot be proven -> honest 'unknown'
    assert "0 proved / 2 unknown" in titles["mul"]
    assert "2 proved" not in titles["mul"]


def test_hover_still_answers_after_codelens():
    uri = "file:///test_codelens_hover.py"
    _open(uri, FIXTURE)
    _lenses(uri)
    r = lsp.handle({"jsonrpc": "2.0", "id": 2, "method": "textDocument/hover",
                    "params": {"textDocument": {"uri": uri},
                               "position": {"line": 1, "character": 4}}})
    assert "path contracts" in r["result"]["contents"]["value"]


def test_lenses_cached_per_document_version():
    uri = "file:///test_codelens_cache.py"
    _open(uri, "def f(n):\n    return n\n")
    first = _lenses(uri)
    again = _lenses(uri)
    assert again == first                       # served from the cache
    lsp.handle({"jsonrpc": "2.0", "method": "textDocument/didChange",
                "params": {"textDocument": {"uri": uri, "version": 2},
                           "contentChanges": [{"text":
                           "def f(n):\n    if n > 0:\n        return 1\n"
                           "    return -1\n"}]}})
    bumped = _lenses(uri)
    assert bumped != first                      # recomputed for version 2
    assert "2 paths" in bumped[0]["command"]["title"]


def test_show_contracts_execute_command():
    uri = "file:///test_codelens_exec.py"
    _open(uri, FIXTURE)
    r = lsp.handle({"jsonrpc": "2.0", "id": 3,
                    "method": "workspace/executeCommand",
                    "params": {"command": "pegrex.showContracts",
                               "arguments": [uri, "classify"]}})
    assert "(n > 0) → 1" in r["result"]
    r = lsp.handle({"jsonrpc": "2.0", "id": 4,
                    "method": "workspace/executeCommand",
                    "params": {"command": "nope", "arguments": []}})
    assert "error" in r                          # unsupported command named


def _frame(msg):
    body = json.dumps(msg).encode()
    return b"Content-Length: %d\r\n\r\n" % len(body) + body


def _parse(raw):
    out, buf = [], raw
    while buf:
        head, sep, rest = buf.partition(b"\r\n\r\n")
        assert sep, raw[:120]
        length = int([l for l in head.split(b"\r\n")
                      if l.lower().startswith(b"content-length:")]
                     [0].split(b":", 1)[1])
        out.append(json.loads(rest[:length]))
        buf = rest[length:]
    return out


def test_framed_stdio_roundtrip_and_malformed_refused():
    server = [sys.executable, "-c",
              "import sys; from pegrex.lsp import serve; "
              "serve(sys.stdin, sys.stdout.buffer)"]
    doc = "file:///test_codelens_stdio.py"
    payload = b"".join(_frame(m) for m in [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "textDocument/didOpen",
         "params": {"textDocument": {"uri": doc, "languageId": "python",
                                     "version": 1, "text": FIXTURE}}},
        {"jsonrpc": "2.0", "id": 2, "method": "textDocument/codeLens",
         "params": {"textDocument": {"uri": doc}}},
        {"jsonrpc": "2.0", "id": 9, "method": "shutdown", "params": {}},
    ])
    r = subprocess.run(server, input=payload, capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr[-300:]
    by_id = {m.get("id"): m for m in _parse(r.stdout) if m.get("id") is not None}
    assert by_id[1]["result"]["capabilities"]["codeLensProvider"]
    assert len(by_id[2]["result"]) == 2

    # malformed frame -> JSON-RPC error -32600, process exits (never hangs)
    r = subprocess.run(server, input=b"Content-Length: 9\r\n\r\nnot json!",
                       capture_output=True, timeout=30)
    assert r.returncode == 0, r.stderr[-300:]
    errors = [m for m in _parse(r.stdout) if "error" in m]
    assert errors and errors[0]["error"]["code"] == -32600
