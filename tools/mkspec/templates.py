"""mkspec.templates -- the rich stub schema + registry.

The 'full' template is intentionally rich: it is the contract between the
generator and the AI agent. Custom stubs: pass --template path/to.json;
any field present in your stub is preserved, missing ones are defaulted.
"""
import copy

TASK_STUB = {
    "id": "",
    "view": "",
    "priority": "P3",
    "severity": "INFO",
    "title": "",
    "lines": [],
    "acceptance_criteria": [],
    "verify": [],
    "estimate": "S",
    "risk": "low",
    "depends_on": [],
    "agent_notes": ""
}

FULL = {
    "schema_version": "1.0",
    "kind": "ai-refactor-spec",
    "meta": {
        "name": "",
        "generated_by": "mkspec",
        "created_at": "",
        "source_sha256": "",
        "language": "",
        "analyzers": [],
        "opus": [],
        "finding_count": 0,
        "profile": "full"
    },
    "preprocess": {
        "language": "",
        "entrypoints": [],
        "source_files": [],
        "dependencies": {"stdlib": [], "third_party": [], "local": []},
        "context": "",
        "read_first": [],
        "constraints": {
            "must_preserve": ["runtime behavior", "cli interface", "public API"],
            "style_guide": "PEP 8",
            "python_version": ">=3.9",
            "max_lines_per_function": 40,
            "allowed_operations": [
                "refactor-internals", "add-tests", "add-docstrings",
                "split-modules", "rename-locals", "extract-helpers"],
            "forbidden_operations": [
                "change-cli-interface", "add-runtime-dependencies",
                "delete-public-symbols", "skip-verify-commands"]
        },
        "environment": {
            "python": "3.12",
            "required_tools": ["python", "tools/secaudit.py"],
            "optional_tools": ["pytest", "mypy", "pydocstyle", "ruff"]
        }
    },
    "analysis": {
        "findings_by_analyzer": {},
        "opus": {},
        "metrics": {},
        "notes": ""
    },
    "tasks": [],
    "postprocess": {
        "expected_artifacts": [],
        "invariants": [
            "all verify commands in tasks pass",
            "module imports cleanly",
            "python -m py_compile succeeds on every touched file"
        ],
        "gates": [
            {"name": "audit_clean", "command": "python tools/secaudit.py <source>",
             "pass_when": "no CRITICAL/HIGH findings remain"},
            {"name": "tests_pass", "command": "python -m pytest -q",
             "pass_when": "exit 0"},
            {"name": "behavior_preserved",
             "command": "run the tool on a fixed sample; diff output",
             "pass_when": "identical output"}
        ],
        "rollback": "git checkout -- <source>",
        "handoff": "human review required if any task has risk == 'medium' or 'high'"
    },
    "agent_directives": {
        "objective": "Execute tasks in priority order; after each task, run its verify commands.",
        "loop": "audit -> fix -> re-verify -> next task; stop when all gates pass.",
        "max_iterations_per_task": 5,
        "report_format": "per-task: id, status(pass/fail), verify output summary; final: gate results",
        "escalate_when": "a verify command fails 5 times, or a task requires a forbidden operation"
    }
}

TEMPLATES = {"full": FULL, "security-only": copy.deepcopy(FULL)}
TEMPLATES["security-only"]["profile"] = "security-only"
