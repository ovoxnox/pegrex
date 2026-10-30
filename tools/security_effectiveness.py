#!/usr/bin/env python3
"""Run the small, labeled PegRex security regression corpus.

This is a reproducible smoke benchmark, not a representative industry benchmark.
It measures the shipped static analyzer against curated positive/fixed pairs and
reports errors as uncovered cases rather than clean results.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dataclasses import replace
from pegrex import security_audit
from pegrex.framework_models import FRAMEWORK_SINKS, MODEL_VERSION
from pegrex.flow import DEFAULT_SINKS, SECRET_SINKS
from pegrex.security_audit import analyze_security_source
from pegrex.security_effectiveness import evaluate_high_severity_mutations, score_rule

CORPUS = ROOT / "tests" / "data" / "security_effectiveness_v120.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--output", type=Path, help="write JSON report; stdout by default")
    args = parser.parse_args(argv)
    cases = json.loads(args.corpus.read_text(encoding="utf-8"))
    analyzed: dict[str, dict] = {}

    def detect(case: dict) -> bool:
        report = analyze_security_source(case["source"], path=case["id"] + ".py")
        analyzed[case["id"]] = report
        return any(row.get("id") == case["rule_id"] for row in report.get("findings", []))

    metrics = []
    for rule_id in sorted({case["rule_id"] for case in cases}):
        selected = [case for case in cases if case["rule_id"] == rule_id]
        metrics.append(score_rule(rule_id, selected,
            lambda source, group=selected: detect(next(case for case in group if case["source"] == source))))

    rules = []
    rule_catalogs = [("framework", sink) for sink in FRAMEWORK_SINKS]
    rule_catalogs += [("default", sink) for sink in DEFAULT_SINKS]
    rule_catalogs += [("secret", sink) for sink in SECRET_SINKS]
    for scope, sink in rule_catalogs:
        group = [case for case in cases if case.get("rule_id") == sink.id]
        if not group:
            continue
        vulnerable = [case for case in group if case["vulnerable"]]
        original_detects = any(detect(case) for case in vulnerable)
        rules.append({"id": sink.id, "severity": sink.severity, "scope": scope,
                      "vulnerable_cases": vulnerable, "original_detects": original_detects})

    # Actual catalog mutation: remove a rule, then replace its signature with an
    # impossible pattern. We only re-analyze fixture text; no source is executed.
    by_id = {row["id"]: row for row in rules}
    def mutation_runner(rule):
        row = by_id[rule["id"]]
        if row["scope"] == "framework":
            owner, attribute = security_audit, "FRAMEWORK_SINKS"
        elif row["scope"] == "default":
            owner, attribute = security_audit, "DEFAULT_SINKS"
        else:
            from pegrex import flow
            owner, attribute = flow, "SECRET_SINKS"
        original_rules = getattr(owner, attribute)
        results = []
        try:
            for mutation_kind in ("remove-rule", "poison-pattern"):
                if mutation_kind == "remove-rule":
                    mutated = tuple(item for item in original_rules if item.id != rule["id"])
                else:
                    mutated = tuple(replace(item, pattern=r"(?!)") if item.id == rule["id"] else item
                                     for item in original_rules)
                setattr(owner, attribute, mutated)
                detected = any(
                    any(finding.get("id") == rule["id"] for finding in
                        analyze_security_source(case["source"], path=case["id"] + ".py").get("findings", []))
                    for case in row["vulnerable_cases"])
                results.append(detected)
        finally:
            setattr(owner, attribute, original_rules)
        return {"original_detects": row["original_detects"], "mutants": results}

    mutation = evaluate_high_severity_mutations(
        [{"id": row["id"], "severity": row["severity"]} for row in rules], mutation_runner)
    errors = [row for metric in metrics for row in metric["results"] if row.get("actual") is None]
    report = {
        "schema": "pegrex.security-effectiveness-benchmark.v1",
        "model_version": MODEL_VERSION,
        "corpus": str(args.corpus.relative_to(ROOT) if args.corpus.is_relative_to(ROOT) else args.corpus),
        "cases": len(cases), "rules_measured": len(metrics), "metrics": metrics,
        "high_severity_mutation_audit": mutation,
        "case_results": [{"id": case["id"], "category": case["category"],
                          "expected_vulnerable": case["vulnerable"],
                          "detected": any(row.get("id") == case["rule_id"]
                                           for row in analyzed.get(case["id"], {}).get("findings", []))}
                         for case in cases],
        "errors": errors,
        "limitations": [
            "curated smoke corpus only; not representative of production code or all framework versions",
            "the corpus includes metamorphic unrelated-helper variants; these increase robustness coverage but are not independent real-world samples",
            "four cases per rule remain a curated regression corpus, not a representative production benchmark",
            "rule mutation operators remove each rule or replace its pattern with an impossible signature; this does not cover every implementation branch",
            "static analysis does not prove exploitability or absence of vulnerabilities"],
    }
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 1 if errors or any(not row["correct"] for metric in metrics for row in metric["results"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
