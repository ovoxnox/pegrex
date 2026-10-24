"""
extension

║  Rule packs as installable extensions (spec-kit shape): a manifest with   
║  id/version/effect/requires/provides, validated by contract.py, over      
║  a rules catalog.  Adding a capability = adding a manifest, not code."""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field

from .contract import (manifest_contract, require, require_list,
                       validate_contract, check_semver)


@dataclass
class Extension:
    """One installed extension: manifest + its rule catalog."""
    manifest: dict
    rules: list[dict] = field(default_factory=list)
    path: pathlib.Path | None = None

    @property
    def id(self) -> str:
        """id(): see module docstring."""
        return self.manifest.get("bundle", {}).get("id", "?")

    @property
    def version(self) -> str:
        """version(): see module docstring."""
        return self.manifest.get("bundle", {}).get("version", "0.0.0")

    @property
    def commands(self) -> list[str]:
        """commands(): see module docstring."""
        return [c.get("name", "?")
                for c in self.manifest.get("provides", {}).get("commands", [])]


class ExtensionError(Exception):
    pass


def load_extension(path: str | pathlib.Path) -> Extension:
    """Load + validate an extension directory or single JSON file.

    Accepts either a manifest.json/catalog.json pair or a combined file with
    both 'manifest' and 'rules' keys."""
    p = pathlib.Path(path)
    raw = json.loads(p.read_text())
    if "manifest" in raw:    # combined file (our catalogs)
        manifest, rules = raw["manifest"], raw.get("rules", [])
    else:                    # manifest + rules.json side by side
        manifest = raw
        rp = p.with_name("rules.json")
        rules = json.loads(rp.read_text())["rules"] if rp.exists() else []
    errors = validate_contract(manifest, [manifest_contract])
    if errors:
        raise ExtensionError("; ".join(str(e) for e in errors))
    return Extension(manifest, rules, p)


def wrap_catalog(catalog_path: str | pathlib.Path, bundle_id: str,
                 version: str = "1.0.0",
                 effect: str = "read-write") -> dict:
    """Promote a bare rules catalog (secrules.json shape) into a full
    extension manifest — the open/closed upgrade path for existing packs."""
    cat = json.loads(pathlib.Path(catalog_path).read_text())
    rules = cat.get("rules", [])
    return {
        "manifest": {
            "bundle": {"id": bundle_id, "version": version, "effect": effect},
            "requires": {"engine_version": "1.0.0"},
            "provides": {"commands": [
                {"name": r["id"], "description": r.get("message", "")[:120]}
                for r in rules]},
        },
        "rules": rules,
    }


def installed_capabilities(extensions: list[Extension]) -> dict[str, list[str]]:
    """capability -> providing extension ids (the provides.commands index)."""
    caps: dict[str, list[str]] = {}
    for ext in extensions:
        for cmd in ext.commands:
            caps.setdefault(cmd, []).append(ext.id)
    return caps
