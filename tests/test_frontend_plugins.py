"""Canonical frontend manifest and observable-soundness contracts."""
import json

import service
from pegrex import cli
from pegrex.core import get_engine
from pegrex.languages import (LANGUAGES, capability_matrix, frontend_manifest,
                              plugin_registry, security_rule_packs,
                              soundness_report, validate_registry)


def test_every_frontend_has_complete_declarative_metadata():
    assert validate_registry() == []
    plugins = plugin_registry()
    assert [row["language"] for row in plugins] == sorted(LANGUAGES)
    assert len(plugins) == 22
    required = {"language", "extensions", "aliases", "parser",
                "source_coordinates", "normalizer", "error_policy", "cfg",
                "expression_lowering", "contracts", "security_rule_packs",
                "capabilities", "maturity", "known_unsupported", "notes"}
    assert all(set(row) == required for row in plugins)
    assert all(row["parser"]["version"] != "unspecified" for row in plugins)
    assert all(row["known_unsupported"] for row in plugins)
    assert all(row["error_policy"] for row in plugins)
    assert json.loads(json.dumps(plugins)) == plugins


def test_manifest_does_not_promote_parsing_to_contract_support():
    lua = frontend_manifest("lua")
    assert lua["maturity"] == "parse-only"
    assert lua["capabilities"] == ["parse"]
    assert lua["contracts"] == {
        "mode": None, "features": [], "handler": None,
        "outcome_renderer": "strip-return"}
    assert "CFG construction" in lua["known_unsupported"]
    python = frontend_manifest("py")
    assert python["source_coordinates"] == "utf8-byte-input->python-char-normalized"
    assert python["parser"]["version"].startswith("tree-sitter-python>=0.25")
    assert "outcomes" in python["contracts"]["features"]
    assert python["security_rule_packs"] == ["secrules.json", "secrules_taint.json"]


def test_security_pack_loading_uses_plugin_kind_and_inheritance():
    assert security_rule_packs(capability="audit") == ("secrules.json",)
    assert security_rule_packs(capability="taint") == ("secrules_taint.json",)
    assert security_rule_packs("typescript") == ("secrules.json",)
    assert security_rule_packs("typescript", capability="audit") == ("secrules.json",)
    assert security_rule_packs("typescript", capability="taint") == ()
    assert security_rule_packs("lua") == ()
    from tools.secaudit import Auditor
    auditor = Auditor()
    assert {path.name for path in auditor.catalog._paths} == set(
        security_rule_packs(capability="audit"))
    assert len(auditor.taint_rules) == 86


def test_soundness_report_is_available_from_core_service_and_cli(capsys):
    report = soundness_report()
    assert report["schema"] == "pegrex.soundness.v1"
    assert report["policy"]["verdicts"] == ["proved", "refuted", "unknown"]
    assert "never infer safety" in report["policy"]["unsupported_analysis"]
    assert len(report["plugins"]) == 22

    core = get_engine().soundness("py")
    assert core.operation == "soundness" and core.status.value == "ok"
    assert core.metadata == {"language": "python", "plugin_count": 1}
    assert core.data["plugins"][0]["language"] == "python"

    wire = service.handle({"method": "soundness", "params": {"language": "c"}})
    assert set(wire) == {"ok", "soundness"}
    assert wire["ok"] is True
    assert wire["soundness"]["plugins"][0]["language"] == "c"

    assert cli.main(["soundness", "--language", "rust"]) == 0
    cli_report = json.loads(capsys.readouterr().out)
    assert cli_report["schema"] == "pegrex.soundness.v1"
    assert cli_report["plugins"][0]["language"] == "rust"


def test_legacy_capability_matrix_shape_is_unchanged():
    assert all(set(row) == {
        "language", "extensions", "parser", "capabilities", "contract_mode",
        "frontend_factory", "comment_prefix", "notes", "parse_adapter",
        "parser_language", "rule_inherits", "contract_handler", "tag_spec",
        "function_tag", "outcome_renderer"} for row in capability_matrix())
