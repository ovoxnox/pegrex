"""
ci -- CI/CD pipeline security analysis

GitHub Actions / GitLab CI anti-patterns: pull_request_target abuse,
unpinned actions, hardcoded secrets, excessive permissions."""
from __future__ import annotations

import pathlib
import re

CHECKS = [
    ("pr-target-checkout", "CRITICAL",
     "pull_request_target with repository checkout (secret exfiltration)",
     re.compile(r"pull_request_target[\s\S]{0,600}?actions/checkout", re.M)),
    ("unpinned-action", "HIGH",
     "action not pinned to a SHA (tag-mutable supply chain)",
     re.compile(r"uses:\s*[\w./-]+@[\w.]+\s*$", re.M)),
    ("hardcoded-secret", "CRITICAL",
     "likely hardcoded secret (token/key/password assignment)",
     re.compile("(?i)(token|secret|password|api[_-]?key)" + chr(92) + "s*[:=]"
                + chr(92) + "s*" + chr(34) + "[^" + chr(34) + "]{16,}" + chr(34))),
    ("excessive-permissions", "MEDIUM",
     "write-all or overly broad permissions",
     re.compile(r"permissions:\s*write-all")),
    ("curl-pipe-shell", "HIGH",
     "curl piped to shell (remote code execution in CI)",
     re.compile(r"curl[^|\n]*\|\s*(ba)?sh")),
]


def analyze_pipeline(path: str) -> list:
    """YAML CI config -> security findings."""
    src = pathlib.Path(path).read_text(encoding="utf-8")
    out = []
    for cid, sev, msg, rx in CHECKS:
        for m in rx.finditer(src):
            line = src[:m.start()].count(chr(10)) + 1
            out.append({"id": f"ci-{cid}", "severity": sev, "line": line,
                        "message": msg,
                        "evidence": m.group(0).strip()[:90]})
    return out
