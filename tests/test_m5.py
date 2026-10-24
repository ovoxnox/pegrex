import subprocess
import sys
from pathlib import Path


def test_m5_transitive_certificate():
    r = subprocess.run([sys.executable, "certs/m5_transitive.py"],
                       cwd=Path(__file__).parent.parent,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "M5 CERTIFICATE" in r.stdout


def test_expand_calls_unit():
    sys.path.insert(0, str(Path(__file__).parent.parent))
    from pegrex.summaries import expand_calls
    clamp = [(frozenset({"(x < 0)"}), "0"), (frozenset({"(not (x < 0))"}), "x")]
    clamp1 = [(frozenset(), "clamp(y) + 1")]
    c1 = expand_calls(clamp1, {"clamp": clamp}, {"clamp": "x"})
    assert ("0 + 1") in [r for _, r in c1]
    f = [(frozenset(), "clamp1(n) * 2")]
    full = expand_calls(f, {"clamp": clamp, "clamp1": c1},
                        {"clamp": "x", "clamp1": "y"})
    results = sorted(r for _, r in full)
    assert results == ["(0 + 1) * 2", "(n + 1) * 2"], results
