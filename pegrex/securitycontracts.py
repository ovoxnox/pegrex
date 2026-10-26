"""Executable security properties over taint evidence."""
from __future__ import annotations
from dataclasses import dataclass
from .flow import DEFAULT_SOURCES
from .frameworkpacks import framework_packs
from .flow import analyze_source
SCHEMA = "pegrex.security-contract.v1"

@dataclass(frozen=True)
class SecurityContract:
    id: str
    source_categories: tuple[str, ...]
    sink_categories: tuple[str, ...]
    required_transformations: tuple[str, ...] = ()
    frameworks: tuple[str, ...] = ("shell",)


def process_execution_contract() -> SecurityContract:
    """Implement process execution contract with the module's explicit API and failure semantics."""
    return SecurityContract("untrusted-never-reaches-process-without-validation",
        ("user-input", "untrusted"), ("process-execution", "command-injection"),
        (r"shlex\.quote", r"validate(?:d)?"), ("shell",))


def check_security_contract(source, contract: SecurityContract, *, path="<memory>.py") -> dict:
    """Implement check security contract with the module's explicit API and failure semantics."""
    packs = framework_packs(contract.frameworks)
    sinks = []
    for rule in packs["sink_rules"]:
        if rule.category in contract.sink_categories and contract.required_transformations:
            rule = type(rule)(**{**rule.__dict__, "sanitizers": contract.required_transformations})
        sinks.append(rule)
    report = analyze_source(source, path=path, source_rules=packs["source_rules"],
                            sink_rules=sinks, report_parameters=False)
    matches = []
    for finding in report["findings"]:
        categories = {row.get("category") for row in finding.get("sources", [])}
        if finding.get("category") in contract.sink_categories and categories & set(contract.source_categories):
            matches.append(finding)
    if any(row["kind"] != "unknown" for row in matches): verdict, holds = "refuted", False
    elif matches or report["unknowns"] or not report["fixed_point"]["stable"]: verdict, holds = "unknown", None
    else: verdict, holds = "proved", True
    unknowns = list(report["unknowns"])
    if any(row["kind"] == "unknown" for row in matches): unknowns.append("possible matching flow lacks complete evidence")
    return {"schema": SCHEMA, "schema_version": 1, "contract": contract.id,
            "verdict": verdict, "holds": holds, "violations": matches,
            "unknowns": sorted(set(unknowns)),
            "evidence": {"fixed_point": report["fixed_point"], "frameworks": contract.frameworks,
                         "required_transformations": contract.required_transformations,
                         "scope": "declared source/sink packs only"}}
