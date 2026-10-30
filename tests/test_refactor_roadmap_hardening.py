"""Regression tests for shared input and process-resource boundaries."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from pegrex.core.engine import CoreEngine
from pegrex.core.models import SourceDocument, Verdict
from pegrex.limits import MAX_SOURCE_BYTES
from pegrex.peg import Node


def test_source_document_rejects_oversized_utf8_before_analysis():
    with pytest.raises(ValueError, match="source input exceeds"):
        SourceDocument("x" * (MAX_SOURCE_BYTES + 1), "python")


def test_source_document_from_path_bounds_the_read(tmp_path: Path):
    source = tmp_path / "large.py"
    source.write_bytes(b"x" * (MAX_SOURCE_BYTES + 1))
    with pytest.raises(ValueError, match="source input exceeds"):
        SourceDocument.from_path(source, "python")


def test_core_engine_returns_structured_unknown_for_oversized_source():
    result = CoreEngine().execute(
        "parse", {"source": "x" * (MAX_SOURCE_BYTES + 1), "language": "python"})
    assert result.verdict == Verdict.UNKNOWN
    assert result.status.value == "error"
    assert any("source input exceeds" in reason for reason in result.unknowns)


def test_node_serialization_is_iterative_for_deep_trees():
    root = Node("leaf", 0, 1, ["x"])
    for index in range(2_000):
        root = Node("nested", 0, 1, [root])
    encoded = CoreEngine._node_dict(root)
    for _ in range(2_000):
        assert encoded["tag"] == "nested"
        encoded = encoded["children"][0]
    assert encoded == {"tag": "leaf", "pos": 0, "endpos": 1, "children": ["x"]}


def test_external_process_output_is_bounded(tmp_path: Path):
    from pegrex.integrations.common import run_argv

    result = run_argv(
        ["head", "-c", "1000000", "/dev/zero"],
        cwd=tmp_path, timeout_ms=5_000, memory_mb=128, max_output_bytes=128)
    assert result["status"] == "unknown"
    assert result["confirmed"] is False
    assert len(result["evidence"]) == 128
    assert any("output was truncated" in reason for reason in result["unknowns"])


def test_external_process_output_limit_rejects_invalid_values(tmp_path: Path):
    from pegrex.integrations.common import run_argv

    for invalid in (-1, True, 8_000_001, "128"):
        result = run_argv(["echo", "x"], cwd=tmp_path, max_output_bytes=invalid)
        assert result["executed"] is False
        assert result["status"] == "unavailable"
        assert result["unknowns"]
    sandbox_env = run_argv(["echo", "x"], cwd=tmp_path, sandbox=True,
                           extra_env={"TOKEN": "not-allowed"})
    assert sandbox_env["executed"] is False
    assert "extra_env is forbidden" in sandbox_env["unknowns"][0]


def test_tree_sitter_normalization_is_iterative_and_preserves_unicode_spans():
    from pegrex.tree_sitter_bridge import normalize_tree

    class FakeNode:
        def __init__(self, type_, children=(), start=0, end=0, named=True):
            self.type = type_
            self.children = list(children)
            self.start_byte = start
            self.end_byte = end
            self.is_named = named

    source = "π🙂x"
    leaf = FakeNode("identifier", start=6, end=7)
    root = FakeNode("module", [leaf], start=0, end=7)
    normalized = normalize_tree(root, source)
    assert normalized.pos == 0 and normalized.endpos == 3
    assert normalized.children[0].pos == 2
    assert normalized.children[0].endpos == 3

    deep = FakeNode("leaf", start=0, end=1)
    for _ in range(2_000):
        deep = FakeNode("nested", [deep], start=0, end=1)
    normalized_deep = normalize_tree(deep)
    for _ in range(2_000):
        assert normalized_deep.tag == "nested"
        normalized_deep = normalized_deep.children[0]
    assert normalized_deep.tag == "leaf"


def test_python_ast_fallback_does_not_resplit_source_per_node(monkeypatch):
    import ast
    from pegrex.python_ast import parse_module

    def forbidden(*args, **kwargs):
        raise AssertionError("quadratic ast.get_source_segment path must not be used")

    monkeypatch.setattr(ast, "get_source_segment", forbidden)
    source = "\n".join(f"def f_{i}(x):\n    return x + {i}" for i in range(300))
    tree = parse_module(source)
    assert tree.tag == "module"
    assert len(tree.children) == 300



def test_patchgate_test_runner_bounds_output_and_timeout(tmp_path: Path):
    from pegrex.patchgate import _run_tests

    noisy = _run_tests(
        [sys.executable, "-c", "print('x' * 100000)"], tmp_path, 5000)
    assert noisy["status"] == "unknown"
    assert "truncated" in noisy.get("reason", "").lower() or "truncated" in noisy.get("output", "").lower()

    invalid = _run_tests([sys.executable, "-c", "print('ok')"], tmp_path, 0)
    assert invalid["status"] == "unknown"
    assert invalid["reason"] == "test-timeout-out-of-range"


def test_proof_replay_refuses_oversized_and_duplicate_key_files(tmp_path: Path):
    from pegrex.proofreplay import main

    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b" " * 5_000_001)
    assert main([str(oversized)]) == 2

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema":"wrong","schema":"pegrex.certificate.v1"}')
    assert main([str(duplicate)]) == 2


def test_assurance_graph_rejects_unbounded_and_malformed_claims():
    from pegrex.assurancegraph import build_assurance_graph

    too_many = build_assurance_graph([{}] * 10_001)
    assert too_many["verdict"] == "unknown"
    assert "budget" in too_many["unknowns"][0]

    malformed = build_assurance_graph([{"id": "x", "kind": "api-contract",
                                        "verdict": "unknown", "evidence": [None]}])
    assert malformed["verdict"] == "unknown"
    assert malformed["nodes"] == []



def test_patchgate_refuses_to_overwrite_concurrent_target_change(tmp_path: Path):
    from pegrex.patchgate import apply_patch_gated

    target = tmp_path / "app.py"
    original = "def f():\n    return 1\n"
    target.write_text(original)

    def mutate_target(staged_path):
        target.write_text("def f():\n    return 99  # concurrent writer\n")
        return {"allowed": True}

    result = apply_patch_gated(
        target, "def f():\n    return 2\n", require_equivalent=False,
        candidate_check=mutate_target, audit_dir=tmp_path / "audit")
    assert not result["applied"]
    assert "target-changed-during-patch-review" in result["unknowns"]
    assert "concurrent writer" in target.read_text()



def test_patchgate_refuses_oversized_source_without_mutating_target(tmp_path: Path):
    from pegrex.patchgate import apply_patch_gated

    target = tmp_path / "app.py"
    original = "def f():\n    return 1\n"
    target.write_text(original)
    result = apply_patch_gated(
        target, "x" * (MAX_SOURCE_BYTES + 1), audit_dir=tmp_path / "audit")
    assert not result["approved"] and not result["applied"]
    assert "exceeds" in result["unknowns"][0]
    assert target.read_text() == original

    target.write_bytes(b"x" * (MAX_SOURCE_BYTES + 1))
    result = apply_patch_gated(target, "def f():\n    return 2\n")
    assert not result["applied"]
    assert "over limit" in result["unknowns"][0]
