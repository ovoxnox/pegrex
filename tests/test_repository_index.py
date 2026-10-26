from __future__ import annotations

import pytest

from pegrex.repository import RepositoryIndex


HELPER = """def helper(x):
    if x < 0:
        return 0
    return x
"""
CALLER = """from helper import helper

def caller(x):
    return helper(x)

def unrelated(x):
    return x + 1
"""


def test_repository_scan_reuses_unchanged_files_and_shared_asts(tmp_path):
    (tmp_path / "a.py").write_text(HELPER)
    (tmp_path / "b.py").write_text(HELPER)
    index = RepositoryIndex(tmp_path)
    first = index.scan()
    assert first["indexed"] == 2
    assert first["shared_ast_entries"] == 1
    assert index.tree("a.py") is index.tree("b.py")

    second = index.scan()
    assert second["last_scan"]["analyzed"] == []
    assert sorted(second["last_scan"]["reused"]) == ["a.py", "b.py"]


def test_repository_edit_and_removal_invalidate_dependents(tmp_path):
    (tmp_path / "helper.py").write_text(HELPER)
    (tmp_path / "caller.py").write_text(CALLER)
    index = RepositoryIndex(tmp_path)
    index.scan()

    (tmp_path / "helper.py").write_text(HELPER.replace("return x\n", "return x + 2\n"))
    changed = index.scan()
    assert "helper.py::helper" in changed["last_scan"]["analyzed"]
    assert "caller.py::caller" in changed["last_scan"]["analyzed"]
    assert "caller.py::unrelated" not in changed["last_scan"]["analyzed"]

    (tmp_path / "helper.py").unlink()
    removed = index.scan()
    assert removed["last_scan"]["removed"] == ["helper.py"]
    assert "caller.py::caller" in removed["last_scan"]["analyzed"]
    assert index.get("helper.py", "helper") is None


def test_parse_failure_is_unknown_and_does_not_replace_last_valid_snapshot(tmp_path):
    path = tmp_path / "module.py"
    path.write_text(HELPER)
    index = RepositoryIndex(tmp_path)
    index.scan()
    valid = index.get("module.py", "helper")
    assert valid["status"] == "ok"

    path.write_text("def helper(:\n")
    broken = index.scan()
    entry = broken["entries"][0]
    assert entry["status"] == "unknown"
    assert entry["stale"] is True
    assert entry["indexed_source_sha256"] == valid["source_sha256"]
    assert entry["source_sha256"] != valid["source_sha256"]
    assert index.get("module.py", "helper") == valid
    assert any("SyntaxError" in reason for reason in broken["unknowns"])

    path.write_text(HELPER)
    repaired = index.scan()
    assert repaired["entries"][0]["status"] == "ok"
    assert repaired["unknown"] == 0


def test_repository_state_round_trip_and_configuration_mismatch(tmp_path):
    (tmp_path / "module.py").write_text(HELPER)
    state = tmp_path / "index.json"
    index = RepositoryIndex(tmp_path, configuration={"mode": "strict"})
    index.scan()
    index.save(state)

    restored = RepositoryIndex.load(tmp_path, state)
    report = restored.scan()
    assert report["last_scan"]["analyzed"] == []
    assert restored.get("module.py", "helper")["status"] == "ok"

    (tmp_path / "module.py").write_text(HELPER + "\ndef other(x):\n    return x\n")
    updated = restored.scan()
    assert "module.py::other" in updated["last_scan"]["analyzed"]
    with pytest.raises(ValueError, match="configuration mismatch"):
        RepositoryIndex.load(tmp_path, state, configuration={"mode": "other"})


def test_explicit_unsupported_file_is_skipped_and_escape_is_refused(tmp_path):
    index = RepositoryIndex(tmp_path)
    entry = index.update_file("notes.unknown", "not source")
    assert entry["status"] == "skipped"
    assert entry["reason"] == "unsupported-language"
    with pytest.raises(ValueError, match="escapes root"):
        index.update_file(tmp_path.parent / "outside.py", "def f():\n    return 1\n")
