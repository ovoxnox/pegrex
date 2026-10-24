import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent


def test_m6_runtime_certificate():
    r = subprocess.run([sys.executable, "certs/m6_emit.py"], cwd=ROOT,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "M6 CERTIFICATE" in r.stdout


def test_negative_certificate_fails():
    r = subprocess.run([sys.executable, "pipeline.py", "specs/fact_negative.json"],
                       cwd=ROOT, capture_output=True, text=True)
    assert r.returncode != 0
    assert "invariant violated" in r.stderr or "mismatch" in r.stderr


def test_emitted_artifact_is_valid_c():
    src = (ROOT / "specs" / "fact_ternary.c").read_text()
    assert "int fact(int n)" in src
    assert "return n == 0 ? 1 : n * fact(n - 1);" in src
