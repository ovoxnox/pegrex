"""Regression tests for the repository's CI trust-boundary configuration."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = (ROOT / ".github" / "workflows" / "ci.yml",
             ROOT / ".github" / "workflows" / "pegrex-gate.yml")


def test_workflows_are_pull_request_safe_and_read_only():
    for path in WORKFLOWS:
        text = path.read_text(encoding="utf-8")
        assert "pull_request_target" not in text
        assert re.search(r"(?m)^permissions:\s*\n\s+contents:\s*read\s*$", text)
        assert text.count("actions/checkout@") == text.count("persist-credentials: false")
        assert "runs-on: ubuntu-latest" in text
        assert "runs-on: self-hosted" not in text
        assert re.search(r"(?m)^\s+timeout-minutes:\s*\d+\s*$", text)


def test_source_controlled_checks_run_in_networkless_runtime():
    for path in WORKFLOWS:
        text = path.read_text(encoding="utf-8")
        assert "--network none" in text
        assert "docker commit" in text
        assert "docker cp requirements-ci.txt" in text
        assert "docker rm -f" in text
        # Dependency setup must not mount the checked-out source. The first
        # workspace mount belongs to the separate, offline runtime container.
        assert text.index("docker cp requirements-ci.txt") < text.index("docker commit")
        assert text.index("docker commit") < text.index("--mount type=bind")
        offline = text.index("--network none")
        # Commands that run repository-controlled Python must be below the
        # networkless-runtime step in the same workflow.
        for command in ("python tools/ci_gate.py", "python -m pytest",
                        "python tools/selfhost.py", "python tools/build_release.py"):
            if command in text:
                assert text.index(command) > offline
        assert "--cap-drop ALL" in text
        assert "--security-opt no-new-privileges" in text
        assert "--pids-limit" in text
        assert "--memory 6g" in text
        assert "--cpus 2" in text
        assert "--read-only" in text
        assert "privileged: true" not in text
        assert "${{ secrets." not in text
        assert "--tmpfs /tmp:rw,nosuid,nodev,size=1g" in text


def test_security_model_documents_operational_controls():
    text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    for phrase in ("disposable", "no private network", "pull_request_target",
                   "publishing/signing", "Docker socket"):
        assert phrase in text
