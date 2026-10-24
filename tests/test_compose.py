import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent


def test_m4_compose_certificate():
    r = subprocess.run([sys.executable, "certs/m4_compose.py"], cwd=ROOT,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "M4 CERTIFICATE" in r.stdout


def test_compose_unit():
    sys.path.insert(0, str(ROOT))
    from pegrex.summaries import compose
    caller = [(frozenset(), "clamp(n) + 1")]
    callee = [(frozenset({"(x < 0)"}), "0"),
              (frozenset({"(not (x < 0))"}), "x")]
    out = compose(caller, "clamp", callee, param="x", arg="n")
    assert out == [(frozenset({"(n < 0)"}), "0 + 1"),
                   (frozenset({"(not (n < 0))"}), "n + 1")], out


def test_compose_no_call_passthrough():
    sys.path.insert(0, str(ROOT))
    from pegrex.summaries import compose
    caller = [(frozenset({"(n = 0)"}), "1")]
    callee = [(frozenset({"(x < 0)"}), "0")]
    assert compose(caller, "clamp", callee, param="x", arg="n") == caller
