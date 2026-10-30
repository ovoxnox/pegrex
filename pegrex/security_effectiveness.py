"""Rule effectiveness and mutation-test metrics over labeled fixtures."""
from __future__ import annotations

def score_rule(rule_id: str, cases: list[dict], detector) -> dict:
    """Each case needs source and vulnerable bool; fixed variants are negatives."""
    tp = fp = tn = fn = 0
    rows = []
    for case in cases:
        expected = bool(case["vulnerable"])
        try: actual = bool(detector(case["source"]))
        except Exception as exc:
            rows.append({"id": case.get("id"), "expected": expected, "actual": None, "error": type(exc).__name__}); continue
        if expected and actual: tp += 1
        elif expected: fn += 1
        elif actual: fp += 1
        else: tn += 1
        rows.append({"id": case.get("id"), "expected": expected, "actual": actual, "correct": expected == actual})
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"schema": "pegrex.rule-effectiveness.v1", "rule_id": rule_id, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(precision, 4), "recall": round(recall, 4), "f1": round(2*precision*recall/(precision+recall), 4) if precision+recall else 0.0,
            "coverage": round((tp+tn+fp+fn)/max(len(cases), 1), 4), "labeled_cases": len(cases), "errors": sum(r.get("actual") is None for r in rows), "results": rows}

def mutation_score(original_detects: bool, mutants: list[bool]) -> dict:
    """A mutant is killed when a detection expected from the rule disappears."""
    killed = sum(1 for detected in mutants if original_detects and not detected)
    return {"schema": "pegrex.rule-mutation.v1", "mutants": len(mutants), "killed": killed,
            "survived": len(mutants)-killed, "score": round(killed/len(mutants), 4) if mutants else None,
            "interpretable": bool(original_detects)}


def regression_fixture_from_confirmed_finding(finding: dict) -> dict:
    """Create a reviewable regression fixture only from a confirmed finding."""
    if finding.get("confirmed") is not True:
        raise ValueError("security regression fixtures require a confirmed finding")
    witness = finding.get("counterexample") or finding.get("witness")
    if not isinstance(witness, dict):
        raise ValueError("confirmed finding requires a structured witness")
    return {"schema": "pegrex.security-regression-fixture.v1",
            "id": str(finding.get("id") or finding.get("rule_id") or "confirmed-finding"),
            "severity": str(finding.get("severity", "HIGH")).upper(),
            "source_sha256": finding.get("source_sha256"),
            "rule_id": finding.get("rule_id") or finding.get("id"),
            "witness": witness,
            "expected": "detect",
            "review_required": True,
            "note": "Fixture data only; review oracle and run in isolated test environment."}


def evaluate_high_severity_mutations(rules: list[dict], isolated_mutation_runner) -> dict:
    """Request mutation evidence for each HIGH/CRITICAL rule via isolated adapter."""
    reports = []
    for rule in rules:
        severity = str(rule.get("severity", "INFO")).upper()
        if severity not in {"HIGH", "CRITICAL"}:
            continue
        rule_id = str(rule.get("id") or rule.get("rule_id") or "")
        try:
            result = isolated_mutation_runner(rule)
            if not isinstance(result, dict) or not isinstance(result.get("mutants"), list):
                reports.append({"rule_id": rule_id, "status": "unknown", "reason": "invalid isolated runner result"})
                continue
            score = mutation_score(bool(result.get("original_detects")), list(map(bool, result["mutants"])))
            reports.append({"rule_id": rule_id, "severity": severity, "status": "measured" if score["interpretable"] else "unknown", **score})
        except Exception as exc:
            reports.append({"rule_id": rule_id, "severity": severity, "status": "unknown", "reason": type(exc).__name__})
    return {"schema": "pegrex.high-severity-mutation-audit.v1", "rules_checked": len(reports),
            "measured": sum(row.get("status") == "measured" for row in reports), "results": reports,
            "note": "The runner must execute mutants in an isolated environment; no runner is supplied by this utility."}
