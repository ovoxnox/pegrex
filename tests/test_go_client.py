"""End-to-end: compiled Go client <-> Python service over JSON-lines pipes.
Skips gracefully when the Go toolchain is unavailable."""
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent
GO = "/tmp/goroot/go/bin/go"
CLIENT = "/tmp/go_client"


def _have_go():
    return os.path.exists(GO) and os.path.exists(CLIENT)


def test_go_client_roundtrip():
    if not _have_go():
        print("SKIP go_client: toolchain not installed")
        return
    svc = subprocess.Popen([sys.executable, "service.py"], cwd=ROOT,
                           stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, text=True)
    try:
        time.sleep(6)   # service startup incl. tree-sitter imports
        r = subprocess.run([CLIENT], cwd=ROOT, capture_output=True, text=True,
                           timeout=90)
        assert r.returncode == 0, r.stderr
        assert '"ok": true' in r.stdout, r.stdout
        assert '"return_statement"' in r.stdout, r.stdout
        assert "ast tag: block" in r.stdout, r.stdout   # parse -> fn body
    finally:
        svc.terminate()
