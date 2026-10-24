import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent


def test_absval_cross_paradigm_spec():
    r = subprocess.run([sys.executable, "pipeline.py", "specs/absval.json"],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "certificate issued" in r.stdout
    assert "[python] specs/absval.py: 2 paths" in r.stdout
    assert "['(n > 0)'] -> n" in r.stdout


def test_service_python_contracts():
    import subprocess as sp
    svc = sp.Popen([sys.executable, "service.py"], cwd=ROOT,
                   stdin=sp.PIPE, stdout=sp.PIPE, stderr=sp.PIPE, text=True)
    try:
        import time
        time.sleep(5)
        req = {"method": "contracts", "params": {
            "language": "python",
            "source": "def absval(n):\n    if n > 0:\n        return n\n    return -n\n"}}
        svc.stdin.write(json.dumps(req) + "\n")
        svc.stdin.flush()
        resp = json.loads(svc.stdout.readline())
        assert resp["ok"], resp
        results = [r for _, r in resp["contract"]]
        assert "n" in results and "-n" in results
    finally:
        svc.terminate()
