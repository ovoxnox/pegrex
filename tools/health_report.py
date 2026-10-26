#!/usr/bin/env python3
"""Validate exact HEALTH task dispositions and render the human report."""
from __future__ import annotations

import collections
import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "specs" / "pegrex_health.spec.json"
DISPOSITIONS = ROOT / "specs" / "pegrex_health.dispositions.json"
OUTPUT = ROOT / "docs" / "HEALTH.md"
SCHEMA = "pegrex.health-dispositions.v1"


def _read_json(path: Path) -> dict:
    """Read one UTF-8 JSON object with a useful file-level error."""
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path.relative_to(ROOT)} must contain a JSON object")
    return value


def _validate(spec: dict, dispositions: dict, report_sha256: str) -> dict:
    """Require an exact, justified policy assignment for every current task."""
    if dispositions.get("schema") != SCHEMA:
        raise ValueError("health dispositions have an unsupported schema")
    if dispositions.get("report_sha256") != report_sha256:
        raise ValueError("health dispositions are stale: report SHA-256 differs")
    tasks = spec.get("tasks")
    policies = dispositions.get("policies")
    assignments = dispositions.get("tasks")
    if not isinstance(tasks, list) or not isinstance(policies, dict) or not isinstance(assignments, dict):
        raise ValueError("health report/dispositions have invalid task or policy containers")
    ids = [task.get("id") for task in tasks if isinstance(task, dict)]
    if len(ids) != len(tasks) or any(not isinstance(task_id, str) for task_id in ids):
        raise ValueError("every health task must have a string ID")
    if len(set(ids)) != len(ids):
        raise ValueError("health task IDs are not unique")
    if set(assignments) != set(ids):
        missing = sorted(set(ids) - set(assignments))
        extra = sorted(set(assignments) - set(ids))
        raise ValueError(f"disposition/task mismatch; missing={missing}, stale={extra}")
    for policy_name, policy in policies.items():
        if not isinstance(policy, dict) or not policy.get("status") or not policy.get("rationale"):
            raise ValueError(f"policy {policy_name!r} lacks status or rationale")
        if not isinstance(policy.get("evidence"), list) or not policy["evidence"]:
            raise ValueError(f"policy {policy_name!r} lacks evidence references")
    unknown_policies = sorted(set(assignments.values()) - set(policies))
    if unknown_policies:
        raise ValueError(f"tasks reference undefined policies: {unknown_policies}")
    return {"tasks": tasks, "policies": policies, "assignments": assignments}


def load_validated() -> tuple[dict, dict, str]:
    """Load and validate the report, exact digest, and complete dispositions."""
    spec = _read_json(SPEC)
    dispositions = _read_json(DISPOSITIONS)
    digest = hashlib.sha256(SPEC.read_bytes()).hexdigest()
    _validate(spec, dispositions, digest)
    return spec, dispositions, digest


def render(spec: dict, dispositions: dict, digest: str) -> str:
    """Render current counts without calling maintenance tasks vulnerabilities."""
    tasks = spec["tasks"]
    policies = dispositions["policies"]
    assignments = dispositions["tasks"]
    severities = collections.Counter(task["severity"] for task in tasks)
    views = collections.Counter(task["view"] for task in tasks)
    policy_counts = collections.Counter(assignments.values())
    status_counts = collections.Counter(
        policies[policy_name]["status"] for policy_name in assignments.values())
    match = re.search(r"python\s+(\d+)", spec.get("meta", {}).get("language", ""))
    files = match.group(1) if match else "unknown"
    lines = [
        "# HEALTH.md - PegRex engine health check",
        "",
        "Regenerate findings with `python pegrex.py health pegrex`, then update exact task dispositions and run `python tools/health_report.py`. Regenerate cognitive/contract evidence with `python tools/selfhost.py`. These are triaged analyzer tasks, not a count of confirmed vulnerabilities.",
        "",
        "## Summary",
        "",
        "| metric | value |",
        "|---|---|",
        f"| engine files analyzed | {files} |",
        f"| total tasks | {len(tasks)} |",
        f"| high severity | {severities['HIGH']} |",
        f"| medium severity | {severities['MEDIUM']} |",
        f"| low severity | {severities['LOW']} |",
        f"| undispositioned tasks | 0 |",
        f"| report SHA-256 | `{digest}` |",
        "",
        "See `docs/SELF.md` for current engine LOC, cognitive hotspots, contract extraction, and explicit UNKNOWN modules.",
        "",
        "## Tasks by analyzer view",
        "",
        "| view | tasks | dispositions |",
        "|---|---|---|",
    ]
    for view in sorted(views):
        view_policies = collections.Counter(
            assignments[task["id"]] for task in tasks if task["view"] == view)
        detail = ", ".join(f"{name}: {count}" for name, count in sorted(view_policies.items()))
        lines.append(f"| {view} | {views[view]} | {detail} |")
    lines.extend(["", "## Dispositions", "",
                  "Every current task ID is assigned to a policy below. `maintenance-open` is explicit non-defect maintenance evidence, not a claim of completed remediation. `accepted-design` records intentional process-local configuration or memoization. `accepted-risk` is a documented operator trust boundary. `false-positive` records why the pattern is not a defect in its actual context.", "",
                  "| policy | status | tasks | rationale | evidence |",
                  "|---|---|---|---|---|"])
    for name in sorted(policy_counts):
        policy = policies[name]
        rationale = policy["rationale"].replace("|", "\\|")
        evidence = "<br>".join(policy["evidence"])
        lines.append(f"| {name} | {policy['status']} | {policy_counts[name]} | {rationale} | {evidence} |")
    lines.extend(["", "## Residual security-pattern tasks", "",
                  "| id | disposition | severity | location |",
                  "|---|---|---|---|"])
    security = [task for task in tasks if task["view"] == "security"]
    if security:
        for task in security:
            title = task["title"].replace("|", "\\|")
            lines.append(f"| {task['id']} | {assignments[task['id']]} | {task['severity']} | {title} |")
    else:
        lines.append("| none | n/a | n/a | no active security-pattern tasks |")
    lines.extend(["", "## Gates", "",
                  "- `python run_tests.py`",
                  "- `python tools/selfhost.py --check`",
                  "- `python tools/health_report.py --check`",
                  "- `python tools/build_skills.py --check`",
                  "",
                  f"Machine-readable findings: `specs/pegrex_health.spec.json` ({len(tasks)} tasks). Exact dispositions: `specs/pegrex_health.dispositions.json`.",
                  ""])
    return "\n".join(lines)


def main() -> int:
    """Validate and write HEALTH.md, or enforce freshness with --check."""
    try:
        spec, dispositions, digest = load_validated()
        body = render(spec, dispositions, digest)
        if "--check" in sys.argv:
            if not OUTPUT.exists() or OUTPUT.read_text(encoding="utf-8") != body:
                print("HEALTH.md or dispositions stale -- run: python tools/health_report.py")
                return 1
            print(f"HEALTH.md is fresh ({len(spec['tasks'])} dispositioned tasks)")
            return 0
        OUTPUT.write_text(body, encoding="utf-8")
        print(f"wrote {OUTPUT} ({len(spec['tasks'])} dispositioned tasks)")
        return 0
    except (OSError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"health report validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
