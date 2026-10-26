#!/usr/bin/env python3
"""Build and verify a deterministic, trimmed PegRex source release archive."""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import zipfile

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = "SHA256SUMS.txt"
EXCLUDED_DIRS = {
    ".git", ".github_cache", ".hypothesis", ".mypy_cache", ".pegrex-cache",
    ".pytest_cache", ".ruff_cache", ".tox", ".venv", "__pycache__", "build",
    "dist", "htmlcov", "node_modules", "pegrex.egg-info",
}
EXCLUDED_SUFFIXES = {".coverage", ".log", ".pyc", ".pyo", ".tmp"}


def release_files(root: Path) -> list[Path]:
    """Return regular source-release files, excluding caches and build products."""
    files = []
    for path in root.rglob("*"):
        relative = path.relative_to(root)
        if any(part in EXCLUDED_DIRS for part in relative.parts):
            continue
        if path.is_symlink():
            raise ValueError(f"release contains a symlink: {relative.as_posix()}")
        if not path.is_file():
            continue
        if relative.as_posix() == MANIFEST or path.suffix in EXCLUDED_SUFFIXES:
            continue
        if path.name in {".DS_Store", "coverage.xml"} or path.suffix == ".zip":
            continue
        files.append(path)
    return sorted(files, key=lambda item: item.relative_to(root).as_posix())


def manifest_bytes(root: Path, files: list[Path]) -> bytes:
    """Hash exact release bytes using the conventional SHA256SUMS format."""
    lines = []
    for path in files:
        name = path.relative_to(root).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}\n")
    return "".join(lines).encode("utf-8")


def build_archive(root: Path, output: Path) -> str:
    """Write a stable ZIP and return its SHA-256 after independent verification."""
    root = root.resolve()
    files = release_files(root)
    if not files:
        raise ValueError("refusing to build an empty release")
    manifest = manifest_bytes(root, files)
    (root / MANIFEST).write_bytes(manifest)
    entries = [(path.relative_to(root).as_posix(), path.read_bytes()) for path in files]
    entries.append((MANIFEST, manifest))
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name, payload in entries:
            path = PurePosixPath(name)
            if path.is_absolute() or ".." in path.parts or not name:
                raise ValueError(f"unsafe archive path: {name}")
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            archive.writestr(info, payload)
    verify_archive(output)
    return hashlib.sha256(output.read_bytes()).hexdigest()


def verify_archive(path: Path) -> None:
    """Verify CRCs, unique safe paths, required files, exclusions, and hashes."""
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or archive.testzip() is not None:
            raise ValueError("archive has duplicate paths or CRC failures")
        for name in names:
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or any(
                    part in EXCLUDED_DIRS for part in pure.parts):
                raise ValueError(f"unsafe or excluded archive path: {name}")
        required = {"README.md", "pyproject.toml", "pegrex/__init__.py", MANIFEST}
        if not required.issubset(names):
            raise ValueError(f"archive lacks required files: {sorted(required - set(names))}")
        manifest = archive.read(MANIFEST).decode("utf-8")
        hashed = set()
        for line in manifest.splitlines():
            digest, name = line.split("  ", 1)
            payload = archive.read(name)
            if hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError(f"manifest hash mismatch: {name}")
            hashed.add(name)
        if hashed != set(names) - {MANIFEST}:
            raise ValueError("manifest/archive file set differs")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true", help="verify without rebuilding")
    args = parser.parse_args()
    try:
        if args.check:
            verify_archive(args.output)
            print(f"verified {args.output} ({hashlib.sha256(args.output.read_bytes()).hexdigest()})")
        else:
            digest = build_archive(ROOT, args.output)
            print(f"wrote {args.output} ({args.output.stat().st_size} bytes, sha256 {digest})")
        return 0
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        parser.exit(1, f"release validation failed: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())
