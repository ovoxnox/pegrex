import gzip
import importlib.util
import io
import pathlib
import tarfile

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _load():
    spec = importlib.util.spec_from_file_location(
        "build_skills", ROOT / "tools" / "build_skills.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_skill_archive_is_reproducible_and_unique():
    mod = _load()
    first = mod.archive_bytes()
    assert first == mod.archive_bytes()
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(first)), mode="r:") as tar:
        members = tar.getmembers()
        names = [m.name for m in members]
        assert len(names) == len(set(names))
        assert names == sorted(names)
        assert all(m.mtime == 0 and m.uid == 0 and m.gid == 0 for m in members)
        assert all(m.isfile() and m.mode == 0o644 for m in members)
        skills = [n for n in names if n.endswith("/SKILL.md")]
        assert len(skills) == len(list((ROOT / "skills").glob("*/SKILL.md")))


def test_committed_skill_archive_is_fresh():
    mod = _load()
    assert (ROOT / "pegrex-skills.tar.gz").read_bytes() == mod.archive_bytes()
