"""Opt-in real Docker integration tests for the restricted plugin worker.

Set PEGREX_PLUGIN_TEST_IMAGE to a trusted local Python image and run on a
throwaway Docker host. These tests deliberately skip without a live daemon/image.
"""
from __future__ import annotations
import os
from pathlib import Path
import shutil
import subprocess

import pytest
from pegrex.plugin_sdk import run_plugin_containerized

IMAGE = os.environ.get("PEGREX_PLUGIN_TEST_IMAGE", "")
DOCKER = shutil.which("docker")


def _docker_ready() -> bool:
    if not DOCKER or not IMAGE:
        return False
    try:
        return subprocess.run([DOCKER, "image", "inspect", IMAGE],
                              stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=3, check=False).returncode == 0 and \
               subprocess.run([DOCKER, "info"], stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=3, check=False).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


pytestmark = pytest.mark.skipif(not _docker_ready(), reason="requires a live Docker daemon and PEGREX_PLUGIN_TEST_IMAGE")


def test_plugin_runs_in_restricted_container(tmp_path: Path):
    (tmp_path / "plugin.py").write_text(
        "def analyze(source):\n    return {'findings': [], 'source_length': len(source)}\n",
        encoding="utf-8")
    result = run_plugin_containerized(tmp_path, "plugin", "print('not executed by test')",
                                      image=IMAGE, timeout_seconds=10)
    assert result["status"] == "ok", result
    assert result["containerized"] is True
    assert result["network_disabled"] is True
    assert result["read_only_plugin_mount"] is True
    assert result["result"]["source_length"] > 0


def test_plugin_timeout_kills_container_and_returns_unknown(tmp_path: Path):
    (tmp_path / "plugin.py").write_text(
        "def analyze(source):\n    while True: pass\n",
        encoding="utf-8")
    result = run_plugin_containerized(tmp_path, "plugin", "x", image=IMAGE,
                                      timeout_seconds=1, max_output_bytes=4096)
    assert result["status"] == "unknown"
    assert "timed out" in result["reason"]
