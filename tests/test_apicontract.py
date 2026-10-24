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


from pegrex.apicontract import agreement, parse_openapi

SPEC = {"openapi": "3.0.0", "paths": {"/add": {"post": {"operationId": "add",
    "parameters": [
        {"name": "a", "required": True, "schema": {"type": "integer"}},
        {"name": "b", "required": True, "schema": {"type": "integer"}}],
    "responses": {"200": {"content": {"application/json": {
        "schema": {"type": "integer"}}}}}}}}}
PY = chr(10).join(["def add(a: int, b: int) -> int:", "    return a + b", ""])
GO = chr(10).join(["package client", "func add(a int, b int) int {",
                   "    return a + b", "}", ""])


def test_schema_parses():
    c = parse_openapi(SPEC)
    assert c["add"]["params"] == {"a": "int", "b": "int"}
    assert c["add"]["returns"] == "int"


def test_agreement():
    assert agreement(PY, GO, SPEC)["agree"] is True


def test_renamed_param_detected():
    out = agreement(PY, GO.replace("b int", "c int"), SPEC)
    assert not out["agree"]
    assert any(d["kind"] == "missing-param" for d in out["drift"])


def test_missing_endpoint_detected():
    out = agreement("", GO, SPEC)
    assert any(d["kind"] == "missing-endpoint" for d in out["drift"])


def test_garbage_schema_refused():
    try:
        parse_openapi({"not": "openapi"})
        assert False
    except ValueError:
        pass
