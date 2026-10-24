try:
    import pytest
except ImportError:
    class _Raises:
        def __init__(self, exc): self.exc = exc
        def __enter__(self): return self
        def __exit__(self, t, v, tb):
            assert t is not None and issubclass(t, self.exc), f"expected {self.exc}"
            return True
    class _PytestShim:
        @staticmethod
        def raises(exc): return _Raises(exc)
    pytest = _PytestShim()


from pegrex import a2a, lsp

BEFORE = chr(10).join(["def classify(n):", "    if n > 0:", "        return 1",
                       "    return -1", ""])
AFTER = BEFORE.replace("return 1", "return -1")


def test_a2a_contracts():
    r = a2a.handle({"jsonrpc": "2.0", "id": 1, "method": "contracts",
                    "params": {"source": BEFORE}})
    assert r["result"] and len(r["result"]) == 2


def test_a2a_verify_patch_counterexample():
    r = a2a.handle({"jsonrpc": "2.0", "id": 2, "method": "verify_patch",
                    "params": {"before": BEFORE, "after": AFTER}})
    assert r["result"]["verified"] is False
    assert r["result"]["counterexample"]["inputs"].get("n") is not None


def test_a2a_malformed_refused():
    for junk in (None, "hello", {"method": "nope", "id": 3},
                 {"method": "contracts", "params": 42}):
        assert "error" in a2a.handle(junk)


def test_lsp_initialize_and_hover():
    r = lsp.handle({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {}})
    assert r["result"]["capabilities"]["hoverProvider"] is True
    doc = "file:///a.py"
    lsp.handle({"jsonrpc": "2.0", "method": "textDocument/didOpen",
                "params": {"textDocument": {"uri": doc, "languageId": "python",
                                            "version": 1, "text": BEFORE}}})
    r = lsp.handle({"jsonrpc": "2.0", "id": 2, "method": "textDocument/hover",
                    "params": {"textDocument": {"uri": doc},
                               "position": {"line": 1, "character": 4}}})
    assert "path contracts" in r["result"]["contents"]["value"]


def test_lsp_malformed_refused():
    for junk in (None, {"method": "nope", "id": 9}):
        assert "error" in lsp.handle(junk)
