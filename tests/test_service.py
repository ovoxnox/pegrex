import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent


def _rpc(proc, req):
    proc.stdin.write(json.dumps(req) + "\n")
    proc.stdin.flush()
    return json.loads(proc.stdout.readline())


def test_service_roundtrip():
    proc = subprocess.Popen([sys.executable, "service.py"], cwd=ROOT,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    try:
        assert _rpc(proc, {"method": "ping"})["pong"] is True
        ast = _rpc(proc, {"method": "parse", "params": {
            "language": "python", "source": "def f(n):\n    return n"}})
        assert ast["ok"] and ast["ast"]["tag"] == "block"
        con = _rpc(proc, {"method": "contracts", "params": {
            "language": "python",
            "source": (ROOT / "specs" / "fact.py").read_text()}})
        assert con["contract"][0][1] == "1"
        bad = _rpc(proc, {"method": "nope"})
        assert bad["ok"] is False
    finally:
        proc.terminate()


def test_service_verify_certificate():
    proc = subprocess.Popen([sys.executable, "service.py"], cwd=ROOT,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    try:
        v = _rpc(proc, {"method": "verify",
                        "params": {"spec": "specs/fact.json"}})
        assert v["ok"] and v["certificate"] and v["name"] == "fact cross-language"
    finally:
        proc.terminate()
