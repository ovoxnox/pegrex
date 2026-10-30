"""Regressions for production API, protocol, and trust-boundary hardening."""
from __future__ import annotations

import ast
import io
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from pegrex import SourceDocument, Verdict
from pegrex.core import get_engine


def test_source_document_rejects_forged_hash():
    with pytest.raises(ValueError, match="sha256 mismatch"):
        SourceDocument("return 1", "python", sha256="0" * 64)


def test_core_does_not_refute_on_unconfirmed_counterexample(monkeypatch):
    from pegrex import semantics

    monkeypatch.setattr(semantics, "verify_patch", lambda *args: {
        "verified": False,
        "counterexample": {"confirmed": False, "inputs": {"n": 1}},
        "note": "bounded candidate only",
    })
    result = get_engine().verify_patch("before.py", "after.py")
    assert result.verdict is Verdict.UNKNOWN
    assert result.status.value == "partial"


def test_core_execute_converts_failures_to_unknown(monkeypatch):
    monkeypatch.setattr(
        "pegrex.languages.parse_source",
        lambda *args: (_ for _ in ()).throw(ValueError("invalid source")),
    )
    result = get_engine().execute("parse", {"source": "?", "language": "python"})
    assert result.status.value == "error"
    assert result.verdict is Verdict.UNKNOWN
    assert result.unknowns and "invalid source" in result.unknowns[0]


def test_test_synthesis_preserves_complete_module_stem(tmp_path, monkeypatch):
    from pegrex import api

    source = tmp_path / "alpha.py"
    coverage = tmp_path / "coverage.lcov"
    source.write_text("def f(n):\n    return n\n", encoding="utf-8")
    coverage.write_text("", encoding="utf-8")
    captured = {}
    monkeypatch.setattr(api, "synthesize_tests", lambda *args: captured.setdefault("args", args) or [])
    api.synthesize_tests_from_coverage(str(source), str(coverage))
    assert captured["args"][-1] == "alpha"


def test_tests_cli_uses_coverage_synthesis_not_program_synthesis(monkeypatch, capsys):
    from argparse import Namespace
    from types import SimpleNamespace
    from pegrex import api
    from pegrex.commands.analysis import _cmd_tests

    captured = {}
    def fake_synthesize(source, lcov):
        captured["arguments"] = (source, lcov)
        return [SimpleNamespace(test_body="def test_generated(): pass")]
    monkeypatch.setattr(api, "synthesize_tests_from_coverage", fake_synthesize)
    monkeypatch.setattr(api, "synthesize", lambda *args: pytest.fail("wrong synthesis API"))
    assert _cmd_tests(Namespace(source="module.py", lcov="coverage.lcov")) == 0
    assert captured["arguments"] == ("module.py", "coverage.lcov")
    assert "test_generated" in capsys.readouterr().out


def test_acp_confines_reads_to_workspace(tmp_path):
    from pegrex.acp import AcpServer

    (tmp_path / "inside.py").write_text("ok", encoding="utf-8")
    (tmp_path.parent / "outside.py").write_text("secret", encoding="utf-8")
    server = AcpServer(str(tmp_path))
    assert server._read("inside.py") == "ok"
    with pytest.raises(ValueError, match="workspace"):
        server._read("../outside.py")
    with pytest.raises(ValueError, match="workspace"):
        server._read(str(tmp_path.parent / "outside.py"))


def test_acp_malformed_first_json_line_returns_error(monkeypatch, tmp_path):
    from pegrex.acp import main

    monkeypatch.setattr("sys.stdin", io.StringIO("not-json\n"))
    output = io.StringIO()
    monkeypatch.setattr("sys.stdout", output)
    assert main(str(tmp_path)) == 0
    response = json.loads(output.getvalue())
    assert response["jsonrpc"] == "2.0"
    assert response["id"] is None
    assert "error" in response


def test_invmarket_rejects_missing_key_and_malformed_entries(tmp_path):
    from pegrex.invmarket import InvMarketError, import_invariants

    registry = tmp_path / "registry.json"
    registry.write_text(json.dumps({"market": {"entries": [None]}}), encoding="utf-8")
    with pytest.raises(InvMarketError, match="key"):
        import_invariants(str(registry))
    with pytest.raises(InvMarketError, match="unsigned"):
        import_invariants(str(registry), key="explicit-key")


def test_insure_requires_explicit_key_and_fails_closed():
    from pegrex.insure import InsureError, quote

    source = ("contract S { function f(uint8 a) public pure returns (uint8) "
              "{ return a + 1; } }")
    with pytest.raises(InsureError, match="key"):
        quote(source)
    result = quote(source, key="explicit-key", type_bits=8)
    assert result["quote"]["status"] == "unknown"
    assert result["quote"]["tier"] == "unknown"
    assert result["quote"]["premium"] is None
    assert result["quote"]["unknowns"]


def test_transpiler_does_not_publish_unverified_candidate(tmp_path, monkeypatch):
    from pegrex import transpiler

    source = tmp_path / "f.py"
    source.write_text("def f(n):\n    return n\n", encoding="utf-8")
    monkeypatch.setattr(transpiler, "certified_python_transpile", lambda _: {
        "target": "python", "code": "candidate", "verified": False,
        "proof": {"verified": False}, "counterexample": None,
    })
    result = transpiler.transpile_certified(str(source), target="javascript")
    assert result["status"] == "unknown"
    assert result["code"] is None
    assert result["candidate_code"] is None
    assert result["unknowns"]


def test_tools_api_manifest_and_structured_invocation(tmp_path):
    from pegrex.toolsapi import invoke, list_tools

    manifest = list_tools()
    names = {row["name"] for row in manifest["tools"]}
    assert manifest["api_version"] == "2.0"
    assert {"core.parse", "release.verify", "impact.simulate", "broker.verify"} <= names
    source = tmp_path / "f.py"
    source.write_text("def f(n):\n    return n\n", encoding="utf-8")
    result = invoke("core.contracts_file", {"path": "f.py"}, workspace=tmp_path)
    assert result["status"] == "ok", result
    assert result["data"]
    assert result["provenance"]["paths"][0]["sha256"]


def test_tools_api_validation_and_path_escape_fail_closed(tmp_path):
    from pegrex.toolsapi import invoke

    unknown = invoke("core.parse", {"source": "x", "language": "python", "typo": True})
    assert unknown["status"] == "error"
    assert unknown["verdict"] == "unknown"
    escaped = invoke("core.audit", {"path": "../outside.py"}, workspace=tmp_path)
    assert escaped["status"] == "error"
    assert "workspace" in escaped["error"]["message"]
    assert escaped["data"] is None


def test_production_cli_uses_tools_api_envelope(tmp_path):
    source = tmp_path / "f.py"
    source.write_text("def f(n):\n    return n\n", encoding="utf-8")
    root = Path(__file__).resolve().parent.parent
    environment = dict(os.environ, PYTHONPATH=str(root))
    command = [sys.executable, "-m", "pegrex.cli", "tool", "core.contracts_file",
               "--workspace", str(tmp_path), "--input", '{"path":"f.py"}',
               "--fail-on-unknown"]
    completed = subprocess.run(command, cwd=root, env=environment,
                               capture_output=True, text=True, timeout=30, check=False)
    assert completed.returncode == 0, completed.stderr
    envelope = json.loads(completed.stdout)
    assert envelope["schema"] == "pegrex.tools-api-envelope.v2"
    assert envelope["status"] == "ok"


def test_mlir_adapter_preserves_both_conditional_successors():
    from pipeline import mlir_frontend

    _, build_cfg, _ = mlir_frontend()
    cfg = build_cfg("""func.func @f(%c: i1) {
^entry:
  cf.cond_br %c, ^yes, ^no
^yes:
  func.return
^no:
  func.return
}
""")
    assert len(cfg.blocks) == 3
    assert len(cfg.edges) == 2
    assert {(edge.src, edge.dst, edge.kind) for edge in cfg.edges} == {
        (0, 1, "then"), (0, 2, "else"),
    }
    assert cfg.edges[0].cond is not None
    assert cfg.edges[1].cond == (cfg.edges[0].cond, "else")


def test_mlir_adapter_refuses_incomplete_or_multiple_functions():
    from pipeline import mlir_frontend

    _, build_cfg, _ = mlir_frontend()
    with pytest.raises(ValueError, match="incomplete"):
        build_cfg("""func.func @f() {
^entry:
  cf.assert %c, "unsupported"
}
""")
    with pytest.raises(ValueError, match="exactly one"):
        build_cfg("""func.func @f() {
^entry:
  func.return
}
func.func @g() {
^entry:
  func.return
}
""")


def test_production_text_streams_have_explicit_utf8_encoding():
    root = Path(__file__).resolve().parent.parent
    missing = []
    for path in [*root.joinpath("pegrex").rglob("*.py"),
                 *root.joinpath("tools").rglob("*.py"),
                 root / "pipeline.py", root / "service.py"]:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = (node.func.id if isinstance(node.func, ast.Name)
                    else node.func.attr if isinstance(node.func, ast.Attribute) else "")
            if name not in {"open", "fdopen", "read_text", "write_text"}:
                continue
            # os.open uses a binary file descriptor plus flags (not a text
            # stream); require explicit encodings only for text-facing APIs.
            if (name == "open" and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "os"):
                continue
            if any(keyword.arg == "encoding" for keyword in node.keywords):
                continue
            mode_index = 0 if isinstance(node.func, ast.Attribute) and name == "open" else 1
            mode = (node.args[mode_index] if len(node.args) > mode_index else
                    next((key.value for key in node.keywords if key.arg == "mode"), None))
            if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and "b" in mode.value:
                continue
            if any(keyword.arg is None for keyword in node.keywords):
                continue
            missing.append(f"{path.relative_to(root)}:{node.lineno}:{name}")
    assert not missing, missing


def test_concolic_does_not_reexecute_opaque_branch_predicates():
    from pegrex.concolic import trace_fn

    calls = []
    def branch_with_side_effect(n):
        def predicate():
            calls.append(n)
            return True
        if predicate():
            return n + 1
        return n

    result = trace_fn(branch_with_side_effect, 3)
    assert result["result"] == 4
    assert calls == [3]
    assert result["opaque_branches"] == 1


def test_http_proposer_rejects_non_http_and_credentialed_endpoints(monkeypatch):
    from pegrex.llmcegis import HTTProposer, LLMProposerError

    monkeypatch.setattr("urllib.request.urlopen",
                        lambda *args, **kwargs: pytest.fail("network must not be attempted"))
    for endpoint in ("file:///etc/passwd", "https://user:secret@example.test/api"):
        with pytest.raises(LLMProposerError, match="http"):
            HTTProposer(endpoint)({})


def test_loop_summary_never_executes_analyzed_source(tmp_path):
    from pegrex.loopsum import LoopSumError, summarize

    marker = tmp_path / "executed"
    source = ("def f(n):\n    i = 0\n    while i < n:\n        i = i + 1\n"
              f"    return __import__('pathlib').Path({str(marker)!r}).touch()\n")
    with pytest.raises(LoopSumError, match="side-effect-free"):
        summarize(source)
    assert not marker.exists()


def test_health_documentation_and_mutable_default_analysis_use_python_ast(tmp_path):
    from pegrex.languages import parse_source
    from tools.mkspec.analyzers.builtin import documentation, quality
    from tools.mkspec.core import AnalysisContext

    source = tmp_path / "sample.py"
    text = ("def documented():\n    \"\"\"Return one.\"\"\"\n    return 1\n\n"
            "def undocumented():\n    return 2\n\n"
            "def safe(items=None):\n    \"\"\"Use a fresh list.\"\"\"\n    items = []\n    return items\n\n"
            "def unsafe(items=[]):\n    \"\"\"Expose a mutable default for analysis.\"\"\"\n    return items\n")
    source.write_text(text, encoding="utf-8")
    context = AnalysisContext(source, "python", text, parse_source("python", text))
    docs = documentation(context)
    assert [row.symbol for row in docs] == ["undocumented"]
    mutable = [row for row in quality(context) if row.check_id == "mutable-default"]
    assert [row.symbol for row in mutable] == ["unsafe"]


def test_health_testing_analyzer_uses_repository_test_references(tmp_path):
    from pegrex.languages import parse_source
    from tools.mkspec.analyzers.builtin import testing
    from tools.mkspec.core import AnalysisContext

    package = tmp_path / "pegrex"
    tests = tmp_path / "tests"
    package.mkdir()
    tests.mkdir()
    (tmp_path / "pyproject.toml").write_text("[project]\nname='x'\n", encoding="utf-8")
    source = package / "sample.py"
    text = "def alpha():\n    return 1\n\ndef beta():\n    return 2\n"
    source.write_text(text, encoding="utf-8")
    (tests / "test_sample.py").write_text(
        "from pegrex.sample import alpha\ndef test_alpha():\n    assert alpha() == 1\n",
        encoding="utf-8")
    tree = parse_source("python", text)
    findings = testing(AnalysisContext(source, "python", text, tree))
    assert [row.symbol for row in findings] == ["beta"]


def test_security_catalog_has_no_rejected_rules_or_framework_style_false_positives():
    from tools.secaudit import JsonCatalog, ROOT, audit_source

    catalog = JsonCatalog(ROOT / "pegrex" / "secrules.json")
    assert catalog.rejected("python") == []
    findings = audit_source("import json\nprint(json.dumps({}))\n", "python")
    ids = {row["id"] for row in findings}
    assert "use-json-response" not in ids
    assert "use-jsonify" not in ids
    assert "PEGREX-RULES-UNKNOWN" not in ids
    assert "eval-detected" not in {row["id"] for row in audit_source(
        "safe_eval(expression, environment)\n", "python")}
    assert "eval-detected" in {row["id"] for row in audit_source(
        "eval(expression)\n", "python")}
    token = "ZXlK" + "A" * 20 + "." + "B" * 20 + "." + "C" * 20
    jwt_ids = {row["id"] for row in audit_source("token = '" + token + "'\n", "python")}
    assert "jwt-base64" in jwt_ids


def test_command_rules_match_real_sinks_not_imports_or_reflection():
    from tools.secaudit import audit_source

    benign = "__import__('pkg')\ngetattr(object, 'name')\n"
    benign_ids = {row["id"] for row in audit_source(benign, "python")}
    assert "dangerous-system-call" not in benign_ids
    assert "strict-cmd-injection" not in benign_ids
    unsafe_ids = {row["id"] for row in audit_source(
        "import os\nos.system(user_command)\n", "python")}
    assert "command-injection-os-system" in unsafe_ids


def test_language_maturity_is_stable_without_hiding_scope_limits():
    from pegrex.languages import LANGUAGES

    experimental = [name for name, spec in LANGUAGES.items() if spec.maturity == "experimental"]
    assert not experimental
    assert LANGUAGES["go"].maturity == "stable"
    assert "goroutines and channel interleaving" in LANGUAGES["go"].known_unsupported
    assert LANGUAGES["tsx"].maturity == "parse-only"


def test_production_cli_engine_errors_are_machine_readable():
    root = Path(__file__).resolve().parent.parent
    environment = dict(os.environ, PYTHONPATH=str(root))
    completed = subprocess.run(
        [sys.executable, "-m", "pegrex.cli", "engine", "not-an-operation"],
        cwd=root, env=environment, capture_output=True, text=True, timeout=30, check=False)
    assert completed.returncode == 1
    envelope = json.loads(completed.stdout)
    assert envelope["status"] == "error"
    assert envelope["verdict"] == "unknown"


def test_legacy_cli_errors_are_structured_without_tracebacks():
    root = Path(__file__).resolve().parent.parent
    environment = dict(os.environ, PYTHONPATH=str(root))
    completed = subprocess.run(
        [sys.executable, "-m", "pegrex.cli", "tool", "core.parse", "--input", "not-json"],
        cwd=root, env=environment, capture_output=True, text=True, timeout=30, check=False)
    assert completed.returncode == 1
    assert "Traceback" not in completed.stderr
    envelope = json.loads(completed.stderr)
    assert envelope["schema"] == "pegrex.cli-error.v1"
    assert envelope["verdict"] == "unknown"


def test_production_cli_json_rejects_duplicates_nonfinite_and_oversize_files(tmp_path):
    from argparse import Namespace
    from pegrex.commands.production import _arguments
    from pegrex.requestlimits import MAX_REQUEST_BYTES
    for text in ('{"source":"a","source":"b","language":"python"}',
                 '{"source":NaN,"language":"python"}',
                 '{"source":1e9999,"language":"python"}'):
        with pytest.raises(ValueError):
            _arguments(Namespace(input=text, input_file=None))
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * (MAX_REQUEST_BYTES + 1))
    with pytest.raises(ValueError, match="exceeds"):
        _arguments(Namespace(input=None, input_file=str(oversized)))


def test_core_validates_arguments_before_dispatch_and_rejects_boolean_budgets(monkeypatch):
    engine = get_engine()
    monkeypatch.setattr(engine, "parse", lambda **_: pytest.fail("parser must not run"))
    missing = engine.execute("parse", {"source": "x"}, disclose_errors=True)
    assert missing.status.value == "error"
    assert "language" in missing.unknowns[0]
    invalid = engine.execute("ironkernel.run", {
        "expression": {}, "inputs": {}, "timeout_ms": True})
    assert invalid.status.value == "error"
    assert "timeout_ms" in invalid.unknowns[0]


def test_core_ast_serializer_refuses_cycles_instead_of_looping():
    class Node:
        tag, pos, endpos = "node", 0, 1
        def __init__(self):
            self.children = []
    node = Node()
    node.children.append(node)
    with pytest.raises(ValueError, match="cyclic"):
        get_engine()._node_dict(node)
    assert get_engine()._node_count(node) == 1


def test_selfhost_cli_uses_repository_tools_path(monkeypatch):
    from argparse import Namespace
    from pegrex.commands.common import ROOT
    from pegrex.commands.tooling import _cmd_selfhost
    captured = {}
    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        return subprocess.CompletedProcess(argv, 0, stdout="fresh\n", stderr="")
    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(SystemExit) as exit_info:
        _cmd_selfhost(Namespace(check=True))
    assert exit_info.value.code == 0
    assert Path(captured["argv"][1]) == ROOT / "tools" / "selfhost.py"


def test_roundtrip_generated_stub_selection_has_no_secret_pattern_finding():
    from tools.secaudit import audit_source
    source = Path("pegrex/roundtrip.py").read_text(encoding="utf-8")
    findings = audit_source(source, "python")
    assert "generic-api-key" not in {row["id"] for row in findings}
