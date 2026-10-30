"""Release archives are deterministic, trimmed, and manifest-verified."""
import hashlib
import importlib.util
from pathlib import Path
import zipfile

import pytest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "build_release_test", ROOT / "tools" / "build_release.py")
release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(release)


def _fixture(root: Path):
    (root / "pegrex").mkdir(parents=True)
    (root / "pegrex" / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    (root / "README.md").write_text("fixture\n", encoding="utf-8")
    (root / "pyproject.toml").write_text("[project]\nname='fixture'\n", encoding="utf-8")
    (root / "SECURITY.md").write_text("fixture security policy\n", encoding="utf-8")
    (root / release.CURRENT_VALIDATION).write_text("fixture validation\n", encoding="utf-8")
    (root / release.SKILLS_ARCHIVE).write_bytes(b"reproducible-skills-fixture")
    (root / "other.tar.gz").write_bytes(b"uncommitted-build-product")
    for name in release.EXCLUDED_FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"trimmed-non-production-artifact")
    cache = root / "pegrex" / "__pycache__"
    cache.mkdir()
    (cache / "stale.pyc").write_bytes(b"stale")


def test_release_is_reproducible_and_excludes_caches(tmp_path):
    root = tmp_path / "source"
    _fixture(root)
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    assert release.build_archive(root, first) == release.build_archive(root, second)
    assert first.read_bytes() == second.read_bytes()
    release.verify_archive(first)
    with zipfile.ZipFile(first) as archive:
        assert "pegrex/__pycache__/stale.pyc" not in archive.namelist()
        assert "other.tar.gz" not in archive.namelist()
        assert release.EXCLUDED_FILES.isdisjoint(archive.namelist())
        assert archive.read(release.SKILLS_ARCHIVE) == b"reproducible-skills-fixture"
        assert archive.read("pegrex/__init__.py") == b"VALUE = 1\n"


def test_release_verifier_rejects_manifest_tampering(tmp_path):
    root = tmp_path / "source"
    _fixture(root)
    output = tmp_path / "release.zip"
    release.build_archive(root, output)
    with zipfile.ZipFile(output, "a") as archive:
        archive.writestr("README.md", "tampered\n")
    with pytest.raises(ValueError, match="duplicate paths|hash mismatch"):
        release.verify_archive(output)


def test_release_verifier_requires_bundled_release_evidence(tmp_path):
    root = tmp_path / "source"
    _fixture(root)
    output = tmp_path / "release.zip"
    release.build_archive(root, output)
    incomplete = tmp_path / "incomplete.zip"
    with zipfile.ZipFile(output) as source, zipfile.ZipFile(incomplete, "w") as target:
        for info in source.infolist():
            if info.filename != "SECURITY.md":
                target.writestr(info, source.read(info))
    with pytest.raises(ValueError, match="SECURITY.md"):
        release.verify_archive(incomplete)


def test_release_verifier_rejects_path_traversal(tmp_path):
    output = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("../escape", "bad")
    with pytest.raises(ValueError, match="unsafe"):
        release.verify_archive(output)
