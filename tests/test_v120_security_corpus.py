from __future__ import annotations
import json
from pathlib import Path

from pegrex.security_audit import analyze_security_source
from pegrex.security_effectiveness import score_rule

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "tests" / "data" / "security_effectiveness_v120.json"


def test_v120_corpus_has_metamorphic_variants_for_every_rule():
    cases = json.loads(CORPUS.read_text(encoding="utf-8"))
    assert len(cases) == 52
    by_rule = {}
    for case in cases:
        by_rule.setdefault(case["rule_id"], []).append(case)
    assert len(by_rule) == 13
    assert all(len(rows) == 4 for rows in by_rule.values())
    assert all(any(row.get("derived_from") for row in rows) for rows in by_rule.values())


def test_metamorphic_helper_variants_preserve_expected_detection():
    cases = json.loads(CORPUS.read_text(encoding="utf-8"))
    for case in cases:
        if not case.get("derived_from"):
            continue
        result = analyze_security_source(case["source"], path=case["id"] + ".py")
        detected = any(row.get("id") == case["rule_id"] for row in result.get("findings", []))
        assert detected is bool(case["vulnerable"]), case["id"]
