"""
contract

Schema-by-contract-tests (after github/spec-kit tests/contract):
a schema is defined by its rejection cases. Errors are addressable
dotted paths, adversarial against YAML/JSON coercion traps:
null-vs-missing, string-where-list, ordering invariants, semver,
per-kind pinning, slug safety, falsy-container rejection."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable

SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]*)?$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
KIND_ORDER = ("extensions", "presets", "steps", "workflows")


@dataclass(frozen=True)
class StructuralError:
    path: str  # dotted, addressable: "bundle.license"
    message: str

    def __str__(self) -> str:
        return f"{self.path}: {self.message}"


def _is_missing(v: Any) -> bool:
    """null counts as missing (spec-kit contract: explicit null == absent)."""
    return v is None


def _err(errors, path, msg):
    errors.append(StructuralError(path, msg))


def require(spec: dict, field: str, path: str, errors) -> Any:
    """Implement require with the module's explicit API and failure semantics."""
    v = spec.get(field)
    if _is_missing(v):
        _err(errors, f"{path}.{field}" if path else field, "required")
        return None
    return v


def require_mapping(spec: dict, field: str, path: str, errors) -> dict | None:
    """Non-mapping rejected INCLUDING falsy (spec-kit: 'including falsy')."""
    v = require(spec, field, path, errors)
    if v is None:
        return None
    if not isinstance(v, dict) or not v:
        _err(errors, _p(path, field), "must be a non-empty mapping")
        return None
    return v


def require_list(spec: dict, field: str, path: str, errors,
                 what: str = "list") -> list | None:
    """String-where-list REJECTED, not split per character."""
    v = require(spec, field, path, errors)
    if v is None:
        return None
    if isinstance(v, str):
        _err(errors, _p(path, field), f"string {field} rejected, not split per character")
        return None
    if not isinstance(v, list):
        _err(errors, _p(path, field), f"must be a {what}")
        return None
    return v


def check_semver(v: Any, path: str, errors) -> None:
    """Implement check semver with the module's explicit API and failure semantics."""
    if not (isinstance(v, str) and SEMVER_RE.match(v)):
        _err(errors, path, f"must be semver (got {v!r})")


def check_slug(v: Any, path: str, errors) -> None:
    """Implement check slug with the module's explicit API and failure semantics."""
    if not (isinstance(v, str) and SLUG_RE.match(v)):
        _err(errors, path, "must be a safe slug")


def check_positive_int(v: Any, path: str, errors) -> None:
    """Implement check positive int with the module's explicit API and failure semantics."""
    if not (isinstance(v, int) and not isinstance(v, bool) and v > 0):
        _err(errors, path, "must be a positive integer")


def check_kind_ordering(items: list[dict], path: str, errors) -> None:
    """components ordered by kind: extensions < presets < steps < workflows."""
    ranks = []
    for i, item in enumerate(items):
        k = item.get("kind", "")
        if k not in KIND_ORDER:
            _err(errors, f"{path}[{i}].kind", f"unknown kind {k!r}")
            continue
        ranks.append(KIND_ORDER.index(k))
    if ranks != sorted(ranks):
        _err(errors, path, f"components must order by kind {list(KIND_ORDER)}")


def check_pinning(items: list[dict], path: str, errors,
                  unpinnable: frozenset = frozenset({"step", "steps"})) -> None:
    """Non-step components must be pinned; steps may be unpinned."""
    for i, item in enumerate(items):
        pinned = bool(item.get("pin") or item.get("version"))
        if item.get("kind", "") not in unpinnable and not pinned:
            _err(errors, f"{path}[{i}]",
                 f"non-step component {item.get('id', '?')!r} must be pinned")


def _p(path: str, field: str) -> str:
    return f"{path}.{field}" if path else field


# ── the contract engine: checks are data; a schema is a check list
Check = Callable[[dict, list], None]


def validate_contract(spec: dict, checks: list[Check]) -> list[StructuralError]:
    """Implement validate contract with the module's explicit API and failure semantics."""
    errors: list[StructuralError] = []
    for check in checks:
        check(spec, errors)
    return errors


# ── the AgentManifest contract (our domain, spec-kit discipline)
def manifest_contract(spec: dict, errors: list) -> None:
    """manifest contract(spec, errors): see module docstring."""
    path = "bundle"
    bundle = require_mapping(spec, "bundle", "", errors)
    if bundle is None:
        return
    bid = require(bundle, "id", path, errors)
    if bid is not None:
        check_slug(bid, "bundle.id", errors)
    ver = require(bundle, "version", path, errors)
    if ver is not None:
        check_semver(ver, "bundle.version", errors)
    effect = bundle.get("effect", "read")
    if effect not in ("read", "write", "read-write"):
        _err(errors, "bundle.effect", "must be read | write | read-write")
    requires = require_mapping(spec, "requires", "", errors)
    if requires is not None:
        eng = require(requires, "engine_version", "requires", errors)
        if eng is not None:
            check_semver(eng, "requires.engine_version", errors)
    provides = require_mapping(spec, "provides", "", errors)
    if provides is not None:
        cmds = require_list(provides, "commands", "provides", errors, what="list of commands")
        if cmds:
            for i, c in enumerate(cmds):
                if not isinstance(c, dict):
                    _err(errors, f"provides.commands[{i}]", "must be a mapping")
                    continue
                require(c, "name", f"provides.commands[{i}]", errors)
                require(c, "description", f"provides.commands[{i}]", errors)
    components = spec.get("components")
    if components is not None:
        if not isinstance(components, list):
            _err(errors, "components", "must be a list")
        else:
            check_kind_ordering(components, "components", errors)
            check_pinning(components, "components", errors)


MANIFEST_CHECKS: list[Check] = [manifest_contract]
