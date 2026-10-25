"""Converted rule deduplication preserves semantics and exposes coverage."""
import json

from tools.secaudit import Auditor, JsonCatalog, PatternScanner, TreeSitterAst
from pegrex.rules import read_rule_pack


def rule(rule_id="same", text="eval\\s*\\(", lang="python", **extra):
    return {"id": rule_id, "langs": [lang], "severity": "HIGH",
            "message": text, "match": {"kind": "call", "text": text}, **extra}


def test_exact_duplicates_only_and_coverage_metadata(tmp_path):
    path = tmp_path / "rules.json"
    rows = [rule(), rule(), rule(text="exec\\s*\\("),
            rule(rule_id="go-only", lang="go"), rule(rule_id="off", disabled=True)]
    path.write_text(json.dumps({"upstream": "upstream/rules", "version": "2026.1",
                                "rules": rows}))
    pack = read_rule_pack(path)
    assert len(pack.records) == 3
    assert len(pack.duplicates) == 1
    assert len(pack.disabled) == 1
    assert pack.packs[0]["upstream"] == "upstream/rules"
    assert pack.packs[0]["version"] == "2026.1"
    assert len(pack.packs[0]["sha256"]) == 64
    coverage = pack.coverage("python", rule_languages={"python"})
    assert coverage["active"] == 2
    assert coverage["inapplicable_rules"] == ["go-only"]
    assert coverage["disabled_rules"] == ["off"]


def test_same_id_different_semantics_execute_independently(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text(json.dumps({"rules": [rule(), rule(), rule(text="exec\\s*\\(")]}))
    catalog = JsonCatalog(path)
    rules = list(catalog.rules("python"))
    assert len(rules) == 2
    assert rules[0].execution_id != rules[1].execution_id
    ast = TreeSitterAst.from_source(
        "def f(x):\n    eval(x)\n    exec(x)\n", "python")
    findings = PatternScanner(catalog).scan(ast)
    assert {finding.id for finding in findings} == {"same"}
    assert {finding.evidence for finding in findings} == {"eval(x)", "exec(x)"}


def test_builtin_packs_are_deduplicated_with_provenance():
    auditor = Auditor()
    assert len(auditor.catalog._pack.records) == 682
    assert len(auditor.taint_rules) == 86
    assert len(auditor.catalog._pack.duplicates) == 12
    assert len(auditor.taint_pack.duplicates) == 2
    coverage = auditor.coverage("python")
    assert coverage["pattern"]["provenance"][0]["pack"] == "secrules.json"
    assert coverage["taint"]["provenance"][0]["pack"] == "secrules_taint.json"
