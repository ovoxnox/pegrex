"""Reproducible, offline audit evidence bundles with cryptographic hashes."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import os
import platform
import zipfile
from pathlib import Path

SCHEMA = "pegrex.reproducible-audit-bundle.v1"
_FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def _bytes(document) -> bytes:
    return (json.dumps(document, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False) + "\n").encode("utf-8")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _versions() -> dict:
    packages = {}
    for name in ("pegrex", "tree-sitter", "tree-sitter-python", "z3-solver",
                 "pytest", "hypothesis"):
        try:
            packages[name] = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            packages[name] = None
    return {"python": platform.python_version(), "packages": packages}


def _source_files(root: Path, output: Path, max_files: int, max_file_bytes: int):
    rows, unknowns = [], []
    for path in sorted(root.rglob("*")):
        if path == output or output in path.parents:
            continue
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            unknowns.append({"path": relative, "reason": "symlink-not-followed"})
            continue
        if not path.is_file():
            continue
        size = path.stat().st_size
        if size > max_file_bytes:
            unknowns.append({"path": relative, "reason": "file-size-limit",
                             "bytes": size, "limit": max_file_bytes})
            continue
        rows.append((path, relative))
        if len(rows) > max_files:
            raise ValueError(f"audit bundle file limit exceeded: {max_files}")
    return rows, unknowns


def create_audit_bundle(root: str | Path, output: str | Path, *, configuration=None,
                        reports=None, coverage=None, include_sources=False,
                        osv_snapshot=None, max_files=10_000, max_file_bytes=16_000_000) -> dict:
    """Create byte-reproducible evidence; wall-clock time is deliberately absent."""
    root, output = Path(root).resolve(), Path(output).resolve()
    if not root.is_dir():
        raise ValueError("audit root is not a directory")
    files, unknowns = _source_files(root, output, max_files, max_file_bytes)
    source_rows = []
    for path, relative in files:
        data = path.read_bytes()
        source_rows.append({"path": relative, "bytes": len(data), "sha256": _sha(data)})
    configuration = configuration or {}
    reports = reports or {}
    coverage = coverage if coverage is not None else {"status": "unknown",
                                                     "reason": "coverage-not-supplied"}
    provenance = {"tool_versions": _versions(), "osv_snapshot": osv_snapshot,
                  "network": "offline", "configuration_sha256": _sha(_bytes(configuration))}
    manifest = {"schema": SCHEMA, "root_name": root.name, "sources": source_rows,
                "artifacts": {}, "provenance": provenance, "unknowns": unknowns,
                "include_sources": include_sources}
    artifacts = {"configuration.json": _bytes(configuration),
                 "evidence/reports.json": _bytes(reports),
                 "evidence/coverage.json": _bytes(coverage)}
    for name, data in artifacts.items():
        manifest["artifacts"][name] = {"bytes": len(data), "sha256": _sha(data)}
    artifacts["manifest.json"] = _bytes(manifest)
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED,
                         compresslevel=9) as archive:
        for name in sorted(artifacts):
            info = zipfile.ZipInfo(name, _FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o600 << 16
            archive.writestr(info, artifacts[name])
        if include_sources:
            for path, relative in files:
                info = zipfile.ZipInfo("sources/" + relative, _FIXED_ZIP_TIME)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = 0o600 << 16
                archive.writestr(info, path.read_bytes())
    return {"schema": SCHEMA, "output": str(output), "sha256": _sha(output.read_bytes()),
            "files": len(source_rows), "status": "unknown" if unknowns else "ok",
            "unknowns": unknowns}


def verify_audit_bundle(bundle: str | Path, *, root: str | Path | None = None) -> dict:
    """Verify packaged hashes and optionally compare current source content."""
    try:
        with zipfile.ZipFile(bundle) as archive:
            names = set(archive.namelist())
            if "manifest.json" not in names:
                return {"ok": False, "reason": "manifest-missing"}
            manifest = json.loads(archive.read("manifest.json"))
            if manifest.get("schema") != SCHEMA:
                return {"ok": False, "reason": "unsupported-schema"}
            for name, expected in manifest["artifacts"].items():
                if name not in names:
                    return {"ok": False, "reason": f"missing:{name}"}
                data = archive.read(name)
                if _sha(data) != expected["sha256"] or len(data) != expected["bytes"]:
                    return {"ok": False, "reason": f"tampered:{name}"}
            if manifest.get("include_sources"):
                for row in manifest["sources"]:
                    name = "sources/" + row["path"]
                    if name not in names or _sha(archive.read(name)) != row["sha256"]:
                        return {"ok": False, "reason": f"tampered:{name}"}
    except (OSError, zipfile.BadZipFile, ValueError, KeyError, TypeError) as error:
        return {"ok": False, "reason": f"unreadable-bundle:{error}"}
    drift = []
    if root is not None:
        root = Path(root)
        for row in manifest["sources"]:
            path = root / row["path"]
            if not path.is_file() or path.is_symlink():
                drift.append({"path": row["path"], "reason": "missing-or-symlink"})
            else:
                digest = _sha(path.read_bytes())
                if digest != row["sha256"]:
                    drift.append({"path": row["path"], "before": row["sha256"], "after": digest})
    return {"ok": True, "stable": not drift, "drift": drift,
            "bundle_sha256": _sha(Path(bundle).read_bytes()),
            "status": manifest.get("unknowns") and "unknown" or "ok"}
