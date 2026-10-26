"""Negative controls for deliberately weakened analyzer components."""
from __future__ import annotations
import time
SCHEMA = "pegrex.analyzer-mutation.v1"


def mutation_controls(cases) -> dict:
    """Each case supplies baseline/weakened callables and a detection predicate.

    A control is killed only when the baseline detects its negative control and
    the deliberately weakened analyzer does not. Errors are UNKNOWN, not kills.
    """
    rows = []
    for case in cases:
        name = case["name"]
        row = {"name": name, "component": case.get("component", "unknown")}
        try:
            baseline = case["baseline"]()
            baseline_detected = case["detects"](baseline) is True
            row.update(baseline=baseline, baseline_detected=baseline_detected)
            if not baseline_detected:
                row.update(status="unknown", reason="baseline negative control failed")
            else:
                weakened = case["weakened"]()
                detected = case["detects"](weakened) is True
                row.update(weakened=weakened, weakened_detected=detected,
                           status="survived" if detected else "killed")
        except Exception as error:
            row.update(status="unknown", reason=f"{type(error).__name__}: {error}")
        rows.append(row)
    unknown = sum(row["status"] == "unknown" for row in rows)
    killed = sum(row["status"] == "killed" for row in rows)
    survived = sum(row["status"] == "survived" for row in rows)
    return {"schema": SCHEMA, "schema_version": 1,
            "verdict": "unknown" if unknown else ("refuted" if survived else "proved"),
            "controls": rows, "killed": killed, "survived": survived,
            "unknowns": [row["name"] for row in rows if row["status"] == "unknown"]}


def standard_negative_controls() -> dict:
    """Run deterministic parser, solver, and security-rule negative controls."""
    import ast
    from .flow import SinkRule, analyze_source
    from .smt import auto_feasible
    def parse_strict():
        """Implement parse strict with the module's explicit API and failure semantics."""
        try:
            ast.parse("def broken(:\n")
            return "accepted"
        except SyntaxError:
            return "rejected"
    source = "import os\nos.system(input())\n"
    return mutation_controls([
        {"name": "parser-rejects-invalid-syntax", "component": "parser",
         "baseline": parse_strict, "weakened": lambda: "accepted",
         "detects": lambda result: result == "rejected"},
        {"name": "solver-rejects-contradiction", "component": "solver",
         "baseline": lambda: auto_feasible(["(x < 0)", "(x > 0)"]),
         "weakened": lambda: True, "detects": lambda result: result is False},
        {"name": "rule-detects-command-flow", "component": "rules",
         "baseline": lambda: analyze_source(source)["findings"],
         "weakened": lambda: analyze_source(source,
             sink_rules=(SinkRule("deliberately-disabled", r"a^"),))["findings"],
         "detects": lambda findings: any(row["id"] == "command-injection" for row in findings)},
    ])
