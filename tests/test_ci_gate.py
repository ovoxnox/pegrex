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

import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from tools.ci_gate import CIGateError, main

ROOT = pathlib.Path(__file__).resolve().parent.parent

CLEAN = {
    "absval.py": ("# ensures: result >= 0\n"
                  "def absval(n):\n    if n >= 0:\n        return n\n"
                  "    return -n\n"),
    "plain.py": "def one():\n    return 1\n",
}
OVER = {"messy.py": ("def messy(n):\n    if n > 0:\n        for i in range(n):\n"
                     "            if i > 0 and n > 3:\n"
                     "                while i < n:\n                    i += 1\n"
                     "    return n\n")}
BROKEN = {"classify.py": ("# requires: n >= 0\n"
                          "def classify(n):\n    if n > 0:\n        return 1\n"
                          "    return -1\n")}


def _w(tmp_path, files):
    for name, src in files.items():
        (tmp_path / name).write_text(src)
    return str(tmp_path)


def _run(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


def test_clean_fixture_passes(tmp_path):
    rc, out = _run(["--fail-on-over", _w(tmp_path, CLEAN)])
    assert rc == 0
    assert "gate: PASS" in out
    assert "SKIPPED" in out and "verify_patch" in out  # no base: named, not silent


def test_over_budget_fails_with_flag(tmp_path):
    rc, out = _run(["--fail-on-over", _w(tmp_path, OVER)])
    assert rc == 1
    assert "messy.py::messy" in out


def test_over_budget_reported_without_flag(tmp_path):
    rc, out = _run([_w(tmp_path, OVER)])
    assert rc == 0                      # reported loudly, not a gate failure
    assert "over-budget: messy.py::messy" in out


def test_violated_contract_always_fails(tmp_path):
    rc, out = _run(["--fail-on-over", _w(tmp_path, BROKEN)])
    assert rc == 1
    assert "violated" in out and "classify" in out


def test_verify_patch_proof_and_counterexample(tmp_path):
    a = tmp_path / "a.py"
    b = tmp_path / "b.py"
    a.write_text("def f(n):\n    if n > 0:\n        return 1\n    return -1\n")
    b.write_text("def f(n):\n    if n <= 0:\n        return -1\n    return 1\n")  # equivalent
    rc, _ = _run(["--base", str(a), "--head", str(b), str(tmp_path)])
    assert rc == 0
    b.write_text("def f(n):\n    if n > 0:\n        return -1\n    return 1\n")
    rc, out = _run(["--base", str(a), "--head", str(b), str(tmp_path)])
    assert rc == 1
    assert "counterexample" in out


def test_staged_outside_git_refuses(tmp_path):
    _w(tmp_path, CLEAN)
    here = os.getcwd()
    os.chdir(tmp_path)
    try:
        try:
            _run(["--staged"])
            raised = None
        except CIGateError as e:
            raised = e
    finally:
        os.chdir(here)
    assert raised is not None, "--staged outside a git repo must refuse"
    assert "refusing to guess" in str(raised)


def test_json_output_three_valued(tmp_path):
    _w(tmp_path, dict(CLEAN, **{"broken.py": "def oops(:\n"}))
    rc, out = _run(["--json", str(tmp_path)])
    assert rc == 0                      # syntax-error file is UNKNOWN, not faked
    doc = json.loads(out)
    assert isinstance(doc["ok"], bool) and doc["files"] == 3
    verdicts = {c["name"]: c["verdict"] for c in doc["checks"]}
    assert all(v in ("pass", "fail", "unknown", "skipped")
               for v in verdicts.values())
    assert verdicts["cognitive-budget"] == "unknown"
    assert verdicts["verify_patch"] == "skipped"
    assert all(isinstance(c["failures"], list) and
               isinstance(c["unknowns"], list) for c in doc["checks"])


def test_staged_happy_path_in_temp_git_repo(tmp_path):
    if subprocess.run(["git", "--version"],
                      capture_output=True).returncode != 0:
        print("git unavailable -- skipping staged happy path (honest skip)")
        return
    _w(tmp_path, CLEAN)
    for args in (["git", "init", "-q"], ["git", "add", "."],
                 ["git", "-c", "user.email=t@pegrex", "-c", "user.name=t",
                  "commit", "-qm", "init"]):
        subprocess.run(args, cwd=tmp_path, check=True)
    (tmp_path / "plain.py").write_text("def one():\n    return 2\n")
    subprocess.run(["git", "add", "plain.py"], cwd=tmp_path, check=True)
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "ci_gate.py"),
                        "--staged"], cwd=tmp_path, capture_output=True,
                       text=True)
    assert r.returncode == 0, r.stderr
    assert "1 file(s)" in r.stdout
