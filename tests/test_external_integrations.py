"""Production contracts for optional external integration backends."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import sys

import pytest

from pegrex.integrations import SCHEMA


def _completed():
    return {"status": "completed", "executed": True, "confirmed": True,
            "returncode": 0, "evidence": "", "unknowns": [], "sandbox": True}


def test_integration_manifest_marks_only_staging_operations_as_mutating():
    from pegrex.toolsapi import list_tools
    tools = {row["name"]: row for row in list_tools()["tools"]}
    expected = {"neural.generate", "neural.verify_candidate", "ironkernel.run",
                "ironkernel.differential", "pythoc.compile", "pythoc.analyze_ir",
                "pythoc.differential"}
    assert expected <= set(tools)
    assert tools["neural.generate"]["mutates_workspace"] is True
    assert tools["pythoc.compile"]["mutates_workspace"] is True
    assert all(tools[name]["mutates_workspace"] is False for name in expected - {
        "neural.generate", "pythoc.compile"})
    assert tools["ironkernel.run"]["trust_claim"] is False


def test_integration_paths_are_workspace_confined(tmp_path):
    from pegrex.toolsapi import invoke
    result = invoke("pythoc.analyze_ir", {"ir_path": "../outside.ll", "llvm_version": "18"},
                    workspace=tmp_path)
    assert result["status"] == "error"
    assert result["verdict"] == "unknown"
    assert "workspace" in result["error"]["message"]


def test_core_engine_integration_failures_are_structured(tmp_path):
    from pegrex.core import get_engine
    source = tmp_path / "candidate.py"
    source.write_text("not python", encoding="utf-8")
    result = get_engine().execute("pythoc.compile", {
        "source_path": str(source), "staging": str(tmp_path / "stage"),
        "entrypoint": "f", "timeout_ms": 1000})
    assert result.operation == "pythoc.compile"
    assert result.status.value in {"partial", "error"}
    assert result.verdict.value == "unknown"
    assert result.unknowns


def test_run_argv_is_argv_only_and_bounded(tmp_path):
    from pegrex.integrations.common import run_argv
    # Python 3.13's virtual-address-space baseline can exceed a 128 MiB
    # RLIMIT_AS even for a trivial child; use a realistic process budget.
    result = run_argv([sys.executable, "-c", "print('ok')"], cwd=tmp_path,
                      timeout_ms=5000, memory_mb=512)
    assert result["status"] == "completed"
    assert result["evidence"].strip() == "ok"
    refused = run_argv("echo no", cwd=tmp_path)
    assert refused["executed"] is False
    assert refused["unknowns"]


def test_sandbox_unavailable_never_falls_back(tmp_path, monkeypatch):
    from pegrex.integrations import common
    monkeypatch.setattr(common.shutil, "which", lambda _: None)
    result = common.run_argv([sys.executable, "-c", "print('unsafe')"],
                             cwd=tmp_path, sandbox=True)
    assert result["status"] == "unavailable"
    assert result["executed"] is False
    assert result["evidence"] == ""


def _fake_neural_backend(path: Path, *, write_source=True, status="generated"):
    path.write_text(f"""import json, pathlib, sys
args = sys.argv[1:]
out = pathlib.Path(args[args.index('--output-dir') + 1])
report = pathlib.Path(args[args.index('--report') + 1])
out.mkdir(parents=True, exist_ok=True)
if {write_source!r}:
    (out / 'generated.rs').write_text('fn main() {{}}\\n', encoding='utf-8')
report.write_text(json.dumps({{'schema': 'pegrex.neural-codegen-backend.v1',
 'status': {status!r}, 'generated_file': 'generated.rs', 'endpoints': 1,
 'error': None if {status!r} == 'generated' else 'rejected'}}), encoding='utf-8')
sys.exit(0 if {status!r} == 'generated' else 2)
""", encoding="utf-8")


def test_neural_generation_is_staged_candidate_with_exact_artifacts(tmp_path):
    from pegrex.integrations.neural_codegen import generate_candidate
    spec = tmp_path / "api.sexp"
    spec.write_text("(api :method GET :path \"/health\")", encoding="utf-8")
    backend = tmp_path / "backend.py"
    _fake_neural_backend(backend)
    staging = tmp_path / "staging"
    result = generate_candidate(str(spec), str(staging), [sys.executable, str(backend)],
                               sandbox=False)  # trusted local fixture; production default is isolated
    assert result["schema"] == SCHEMA
    assert result["status"] == "generated"
    assert result["verdict"] == "unknown"
    assert result["candidate"] is True and result["promotion_allowed"] is False
    generated = next(row for row in result["artifacts"] if row["kind"] == "rust-source")
    assert generated["sha256"] == hashlib.sha256((staging / "generated.rs").read_bytes()).hexdigest()


def test_neural_success_without_artifact_or_rejection_is_unknown(tmp_path):
    from pegrex.integrations.neural_codegen import generate_candidate
    spec = tmp_path / "api.sexp"
    spec.write_text("(api)", encoding="utf-8")
    for index, (write_source, status) in enumerate(((False, "generated"), (True, "rejected"))):
        backend = tmp_path / f"backend{index}.py"
        _fake_neural_backend(backend, write_source=write_source, status=status)
        result = generate_candidate(str(spec), str(tmp_path / f"stage{index}"),
                                    [sys.executable, str(backend)], sandbox=False)
        assert result["status"] == "unknown"
        assert result["verdict"] == "unknown"
        assert result["unknowns"]


def test_neural_verifier_blocks_stubs_and_does_not_claim_intent(tmp_path):
    from pegrex.integrations.neural_codegen import verify_candidate
    (tmp_path / "generated.rs").write_text(
        "struct User { // TODO: define fields\n}\nfn main() {}\n", encoding="utf-8")
    result = verify_candidate(str(tmp_path))
    assert result["verdict"] == "unknown"
    assert result["promotion_allowed"] is False
    assert result["incomplete"]
    assert any("compilation" in row for row in result["unknowns"])
    assert any("intent" in row for row in result["unknowns"])


def test_neural_compilation_check_requires_sandbox_and_still_not_production(tmp_path, monkeypatch):
    from pegrex.integrations import neural_codegen
    (tmp_path / "generated.rs").write_text("fn main() {}\n", encoding="utf-8")
    observed = {}
    def fake(argv, **kwargs):
        observed.update(kwargs)
        return _completed()
    monkeypatch.setattr(neural_codegen, "run_argv", fake)
    result = neural_codegen.verify_candidate(str(tmp_path), check_argv=["cargo", "check", "--offline"])
    assert observed["sandbox"] is True
    assert result["compilation"]["status"] == "completed"
    assert result["verdict"] == "unknown"
    assert result["promotion_allowed"] is False


def _expression():
    return {"op": "add", "args": [{"op": "arg", "name": "x"}, {"op": "const", "value": 1.0}]}


def test_ironkernel_expression_and_input_validation_fail_closed():
    from pegrex.integrations.ironkernel_backend import differential, run_expression
    bad = run_expression({"op": "exec", "args": []}, {"x": [1]})
    assert bad["status"] == "unknown"
    assert "unsupported" in bad["unknowns"][0]
    assert differential(_expression(), {"x": [1], "y": [1, 2]})["verdict"] == "unknown"
    assert run_expression(_expression(), {"x": [float("nan")]})["verdict"] == "unknown"
    deep = current = {}
    for _ in range(40):
        current.update({"op": "neg", "args": [{}]})
        current = current["args"][0]
    current.update({"op": "const", "value": 1})
    assert run_expression(deep, {"x": [1]})["status"] == "unknown"


def _iron_result(observed, expected):
    return {"schema": "pegrex.ironkernel-worker.v1", "input_sha256": "abc",
            "backend_version": "1.0.0", "observed": observed, "expected": expected,
            "execution": _completed()}


def test_ironkernel_matching_samples_remain_unknown(monkeypatch):
    from pegrex.integrations import ironkernel_backend as backend
    monkeypatch.setattr(backend, "_execute", lambda *args, **kwargs: _iron_result([2.0], [2.0]))
    result = backend.differential(_expression(), {"x": [1.0]})
    assert result["observations_match"] is True
    assert result["verdict"] == "unknown"
    assert "do not prove" in result["unknowns"][0]


def test_ironkernel_mismatch_requires_confirmed_replay(monkeypatch):
    from pegrex.integrations import ironkernel_backend as backend
    monkeypatch.setattr(backend, "_execute", lambda *args, **kwargs: _iron_result([9.0], [2.0]))
    result = backend.differential(_expression(), {"x": [1.0]})
    assert result["verdict"] == "refuted"
    assert result["counterexample"]["confirmed"] is True
    assert result["counterexample"]["replayed"] is True
    assert result["counterexample"]["inputs"] == {"x": 1.0}


def test_ironkernel_nonreproducible_mismatch_is_unknown(monkeypatch):
    from pegrex.integrations import ironkernel_backend as backend
    rows = iter([_iron_result([9.0], [2.0]), _iron_result([2.0], [2.0])])
    monkeypatch.setattr(backend, "_execute", lambda *args, **kwargs: next(rows))
    result = backend.differential(_expression(), {"x": [1.0]})
    assert result["verdict"] == "unknown"
    assert "not reproducible" in result["unknowns"][0]


def test_ironkernel_nonfinite_policy_is_not_silently_clean(monkeypatch):
    from pegrex.integrations import ironkernel_backend as backend
    monkeypatch.setattr(backend, "_execute", lambda *args, **kwargs: _iron_result(
        [{"nonfinite": "nan"}], [{"nonfinite": "nan"}]))
    result = backend.differential(_expression(), {"x": [1.0]})
    assert result["verdict"] == "unknown"
    assert "non-finite" in result["unknowns"][0]


def test_pythoc_llvm_analysis_is_versioned_and_scoped(tmp_path):
    from pegrex.integrations.pythoc_backend import analyze_ir
    ir = tmp_path / "candidate.ll"
    ir.write_text("""define i32 @f(i1 %c) {
entry:
  br i1 %c, label %yes, label %no
yes:
  ret i32 1
no:
  ret i32 0
}
""", encoding="utf-8")
    result = analyze_ir(str(ir), "18")
    assert result["verdict"] == "proved"
    assert len(result["ir_analysis"]["functions"][0]["edges"]) == 2
    assert "not memory safety" in result["scope"]
    unsupported = analyze_ir(str(ir), "99")
    assert unsupported["verdict"] == "unknown"
    assert unsupported["unknowns"]


def test_pythoc_compile_uses_sandbox_and_checks_worker_hashes(tmp_path, monkeypatch):
    from pegrex.integrations import pythoc_backend
    source = tmp_path / "source.py"
    source.write_text("# typed PythoC source\n", encoding="utf-8")
    observed = {}
    ir_text = "define i32 @f() {\nentry:\n  ret i32 1\n}\n"
    def fake(argv, **kwargs):
        observed.update(kwargs)
        root = Path(kwargs["cwd"])
        staged_source = root / "candidate.py"
        (root / "candidate.ll").write_text(ir_text, encoding="utf-8")
        (root / "backend-report.json").write_text(json.dumps({
            "schema": "pegrex.pythoc-worker.v1", "status": "compiled",
            "ir_sha256": hashlib.sha256(ir_text.encode()).hexdigest(),
            "source_sha256": hashlib.sha256(staged_source.read_bytes()).hexdigest(),
            "llvm_version": [18, 0, 0], "llvm_ir_verified": True}), encoding="utf-8")
        return _completed()
    monkeypatch.setattr(pythoc_backend, "run_argv", fake)
    result = pythoc_backend.compile_source(str(source), str(tmp_path / "stage"), "f")
    assert observed["sandbox"] is True
    assert result["status"] == "compiled"
    assert result["verdict"] == "unknown"
    assert result["promotion_allowed"] is False
    assert result["ir_analysis"]["verdict"] == "proved"


def test_pythoc_worker_identity_mismatch_is_unknown(tmp_path, monkeypatch):
    from pegrex.integrations import pythoc_backend
    source = tmp_path / "source.py"
    source.write_text("# candidate\n", encoding="utf-8")
    def fake(argv, **kwargs):
        root = Path(kwargs["cwd"])
        (root / "candidate.ll").write_text("define i32 @f() { ret i32 1 }", encoding="utf-8")
        (root / "backend-report.json").write_text(json.dumps({
            "schema": "pegrex.pythoc-worker.v1", "status": "compiled",
            "ir_sha256": "bad", "source_sha256": "bad", "llvm_version": [18]}), encoding="utf-8")
        return _completed()
    monkeypatch.setattr(pythoc_backend, "run_argv", fake)
    result = pythoc_backend.compile_source(str(source), str(tmp_path / "stage"), "f")
    assert result["status"] == "unknown"
    assert "identity mismatch" in result["unknowns"][0]


def test_assurance_invalidates_exact_integration_artifacts():
    from pegrex.assurancegraph import build_assurance_graph, invalidate_assurance
    from pegrex.integrations.assurance import assurance_claim
    result = {"schema": SCHEMA, "backend": "pythoc", "operation": "analyze_ir",
              "verdict": "proved", "unknowns": [],
              "artifacts": [{"kind": "llvm-ir", "path": "candidate.ll", "sha256": "a" * 64}]}
    claim = assurance_claim(result, "cfg", "CFG parsed under LLVM 18")
    graph = build_assurance_graph([claim])
    assert graph["verdict"] == "proved"
    upstream = graph["edges"][0]["target"]
    changed = invalidate_assurance(graph, {upstream: {"sha256": "b" * 64}})
    assert changed["verdict"] == "unknown"
    assert changed["invalidated_edges"]
