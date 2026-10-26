#!/usr/bin/env python
"""Build a reproducible, duplicate-free archive of the packaged agent skills."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import pathlib
import tarfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE = ROOT / "skills"
OUTPUT = ROOT / "pegrex-skills.tar.gz"


def skill_files() -> list[pathlib.Path]:
    files = sorted(p for p in SOURCE.rglob("*") if p.is_file())
    names = [p.relative_to(SOURCE).as_posix() for p in files]
    if len(names) != len(set(names)):
        raise ValueError("duplicate skill archive paths")
    skill_dirs = [p for p in SOURCE.iterdir() if p.is_dir()]
    missing = [p.name for p in skill_dirs if not (p / "SKILL.md").is_file()]
    if missing:
        raise ValueError(f"skill directories missing SKILL.md: {missing}")
    return files


def archive_bytes() -> bytes:
    """Return stable gzip/tar bytes independent of wall clock and host metadata."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT, encoding="utf-8") as tar:
        for path in skill_files():
            name = path.relative_to(SOURCE).as_posix()
            payload = path.read_bytes()
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mtime = 0
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            tar.addfile(info, io.BytesIO(payload))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, mtime=0) as gz:
        gz.write(raw.getvalue())
    return compressed.getvalue()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true",
                        help="fail if the committed archive differs from source")
    args = parser.parse_args(argv)
    payload = archive_bytes()
    if args.check:
        if not OUTPUT.exists() or OUTPUT.read_bytes() != payload:
            print("skill archive stale -- run: python tools/build_skills.py")
            return 1
        print(f"skill archive is fresh ({hashlib.sha256(payload).hexdigest()})")
        return 0
    OUTPUT.write_bytes(payload)
    print(f"wrote {OUTPUT} ({len(payload)} bytes, "
          f"sha256 {hashlib.sha256(payload).hexdigest()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
