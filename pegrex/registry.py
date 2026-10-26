"""
registry — self-certifying package registry 

║  A package certifies itself: specmine (Daikon-style) mines every   
║  file's proven path-contract invariants, bundled into a signed          
║  manifest (HMAC attest, via pegrex.attest). The registry tracks, 
║  per package name, the last-published version's proven set. Publishing 
║  a new version refuses (naming exactly which property, in which file)  
║  if anything the OLD version proved is no longer provable -- a         
║  package's own proven guarantees are a trust boundary a dependent can  
║  build on; silently losing one is a regression even if every unit test 
║  still passes."""

from __future__ import annotations

import json
import os
import pathlib
import tempfile

from .attest import hmac_sign, hmac_verify
from .specmine import mine


def certify_package(name: str, version: str, source_files: dict, key: str) -> dict:
    """source_files: {logical_filename: python_source_text}. Mines each
    file's proven invariants (specmine) and signs the resulting manifest
    -- the package's own self-certification, not a third party's claim."""
    certified = {}
    for fname, src in source_files.items():
        fd, path = tempfile.mkstemp(suffix=".py")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(src)
            report = mine(path)
        finally:
            os.unlink(path)
        certified[fname] = {"proven": report["proven"]}
    body = {"name": name, "version": version, "certified": certified}
    return {**body, "signature": hmac_sign(body, key)}


def verify_package(manifest: dict, key: str) -> dict:
    """Independent re-verification of a certified manifest's signature."""
    if not isinstance(manifest, dict):
        return {"ok": False, "reason": "not a manifest"}
    body = {k: v for k, v in manifest.items() if k != "signature"}
    sig = manifest.get("signature")
    if not hmac_verify(body, key, sig):
        return {"ok": False, "reason": "signature mismatch (tampered or wrong key)"}
    return {"ok": True, "name": body.get("name"), "version": body.get("version")}


def load_registry(path) -> dict:
    """Implement load registry with the module's explicit API and failure semantics."""
    p = pathlib.Path(path)
    if not p.exists():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def save_registry(path, registry: dict) -> None:
    """Implement save registry with the module's explicit API and failure semantics."""
    pathlib.Path(path).write_text(
        json.dumps(registry, indent=1, sort_keys=True) + "\n", encoding="utf-8")


def find_regressions(old_manifest: dict, new_manifest: dict) -> list:
    """Every proven property in old_manifest's files that is no longer
    proven in the corresponding new_manifest file -- a removed/renamed
    file counts as losing everything it once proved. Named per
    (file, property), not just a count: a regression report must say
    exactly what broke."""
    regressions = []
    old_certified = old_manifest.get("certified", {})
    new_certified = new_manifest.get("certified", {})
    for fname, old_info in sorted(old_certified.items()):
        new_info = new_certified.get(fname)
        old_proven = set(old_info.get("proven", []))
        new_proven = set(new_info.get("proven", [])) if new_info else set()
        for prop in sorted(old_proven - new_proven):
            regressions.append({"file": fname, "property": prop})
    return regressions


def publish(name: str, version: str, source_files: dict, key: str,
           registry_path) -> dict:
    """Certify the new version, then refuse if it regresses the
    previously-registered version's proven properties. The registry only
    advances to the new version on success -- a refused publish leaves
    the old, still-good version as the registered one."""
    new_manifest = certify_package(name, version, source_files, key)
    registry = load_registry(registry_path)
    old_manifest = registry.get(name)
    if old_manifest is not None:
        v = verify_package(old_manifest, key)
        if not v["ok"]:
            return {"status": "refused", "layer": "integrity",
                    "reason": f"registered manifest for {name!r} failed "
                              f"its own signature check: {v['reason']}"}
        regressions = find_regressions(old_manifest, new_manifest)
        if regressions:
            return {"status": "refused", "layer": "regression",
                    "regressions": regressions,
                    "old_version": old_manifest["version"],
                    "new_version": version}
    registry[name] = new_manifest
    save_registry(registry_path, registry)
    return {"status": "published", "name": name, "version": version,
            "proven_counts": {f: len(info["proven"])
                              for f, info in new_manifest["certified"].items()}}
