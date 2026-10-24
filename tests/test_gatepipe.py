import http.client
import io
import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

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

from pegrex.gatepipe import (GatePipeError, filter_stdio, gate, serve, stop)

GOOD = "def absval(n):\n    if n >= 0:\n        return n\n    return -n\n"


def test_gate_verifies_true_claim():
    out = gate(GOOD, claim="the result is non-negative")
    assert out["verdict"] == "verified"
    assert out["proven_candidates"] == ["result >= 0"]
    assert len(out["contracts"]) == 2 and len(out["paths"]) == 2


def test_gate_refutes_false_claim_with_counterexample():
    out = gate(GOOD, claim="the result is non-positive")
    assert out["verdict"] == "refused"
    cx = out["counterexample"]
    assert cx["inputs"] == {"n": -1}
    assert cx["result_value"] == 1
    assert out["failing_contract"] == "result <= 0"
    assert '"n": -1' in out["next_turn_prompt"]
    assert "result <= 0" in out["next_turn_prompt"]
    assert "Your previous code violated" in out["next_turn_prompt"]


def test_gate_contracts_only_mode():
    out = gate(GOOD)
    assert out["verdict"] == "verified"
    assert out["claim"] is None
    assert out["contracts"]


def test_gate_empty_code_refused():
    out = gate("   ")
    assert out["verdict"] == "refused"


def test_gate_unparseable_code_refused():
    out = gate("def broken(:\n  return", claim="the result is non-negative")
    assert out["verdict"] == "refused"
    assert "next_turn_prompt" in out


@pytest.fixture()
def server():
    srv = serve()
    host, _, port = srv["url"].partition("://")[2].partition(":")
    yield srv, host, int(port)
    stop(srv)


def _post(host, port, path, obj, keep=None):
    c = keep or http.client.HTTPConnection(host, port, timeout=10)
    c.request("POST", path, body=json.dumps(obj),
              headers={"Content-Type": "application/json"})
    resp = c.getresponse()
    body = json.loads(resp.read() or b"{}")
    status = resp.status
    if keep is None:
        c.close()
    return status, body


def test_server_post_verified(server):
    _, host, port = server
    st, b = _post(host, port, "/gate",
                  {"code": GOOD, "claim": "the result is non-negative"})
    assert st == 200 and b["status"] == "verified"


def test_server_post_refused_with_counterexample(server):
    _, host, port = server
    st, b = _post(host, port, "/gate",
                  {"code": GOOD, "claim": "the result is non-positive"})
    assert st == 422 and b["status"] == "refused"
    assert b["counterexample"]["inputs"] == {"n": -1}


def test_server_health(server):
    srv, host, port = server
    c = http.client.HTTPConnection(host, port, timeout=10)
    c.request("GET", "/health")
    resp = c.getresponse()
    body = json.loads(resp.read())
    c.close()
    assert resp.status == 200
    assert body["ok"] is True and body["engine"] == "pegrex"
    assert body["posture"] == "analysis-only; no code execution"


def test_server_404s(server):
    _, host, port = server
    st, _ = _post(host, port, "/nope", {"code": GOOD})
    assert st == 404
    c = http.client.HTTPConnection(host, port, timeout=10)
    c.request("GET", "/nope")
    resp = c.getresponse()
    resp.read()
    c.close()
    assert resp.status == 404


def test_server_localhost_only_posture():
    with pytest.raises(GatePipeError):
        serve("0.0.0.0")
    with pytest.raises(GatePipeError):
        serve("192.168.0.1")


def test_server_never_executes_received_code(server, tmp_path):
    _, host, port = server
    marker = str(tmp_path / "PWNED.txt")
    sneaky = (f"def sneaky(n):\n"
              f"    open({marker!r}, 'w').write('pwned')\n"
              f"    return n\n")
    st, b = _post(host, port, "/gate",
                  {"code": sneaky, "claim": "the result is non-negative"})
    assert st in (200, 422)
    assert not pathlib.Path(marker).exists()


def test_server_malformed_json_400_keepalive(server):
    _, host, port = server
    c = http.client.HTTPConnection(host, port, timeout=10)
    c.request("POST", "/gate", body="{not json",
              headers={"Content-Type": "application/json"})
    resp = c.getresponse()
    body = json.loads(resp.read())
    assert resp.status == 400 and body["status"] == "error"
    c.request("GET", "/health")            # same connection must survive
    resp2 = c.getresponse()
    ok = json.loads(resp2.read())
    c.close()
    assert resp2.status == 200 and ok["ok"] is True


def test_server_signed_responses_with_key():
    srv = serve(key="sign-key")
    try:
        host, _, port = srv["url"].partition("://")[2].partition(":")
        st, b = _post(host, int(port), "/gate", {"code": GOOD})
        assert st == 200 and "signature" in b
        from pegrex.attest import hmac_verify
        assert hmac_verify({k: v for k, v in b.items() if k != "signature"},
                           "sign-key", b["signature"])
    finally:
        stop(srv)


def test_filter_stdio_pipe_mode(monkeypatch=None):
    import pegrex.gatepipe as gp
    lines = json.dumps({"code": GOOD, "claim": "the result is non-negative"}) \
        + "\n" + "{bad json\n"
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO(lines)
    sys.stdout = io.StringIO()
    try:
        gp.filter_stdio()
        out_lines = [json.loads(l) for l in sys.stdout.getvalue().splitlines()]
    finally:
        sys.stdin, sys.stdout = old_in, old_out
    assert out_lines[0]["verdict"] == "verified"
    assert out_lines[1]["status"] == "error"
