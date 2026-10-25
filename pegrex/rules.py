"""Canonical converted-rule deduplication, provenance, and coverage reporting."""
from __future__ import annotations

import hashlib
import json
import pathlib
from dataclasses import dataclass, field


@dataclass(frozen=True)
class RuleOrigin:
    pack: str
    upstream: str
    version: str
    index: int

    def to_dict(self) -> dict:
        return {"pack": self.pack, "upstream": self.upstream,
                "version": self.version, "index": self.index}


@dataclass(frozen=True)
class RuleRecord:
    rule: dict
    origin: RuleOrigin
    semantics: str


@dataclass
class RulePack:
    records: list[RuleRecord] = field(default_factory=list)
    disabled: list[RuleRecord] = field(default_factory=list)
    duplicates: list[dict] = field(default_factory=list)
    packs: list[dict] = field(default_factory=list)

    @property
    def rules(self) -> list[dict]:
        return [record.rule for record in self.records]

    def catalog_version(self) -> str:
        """Exact, content-defined version of this executable catalog snapshot."""
        identity = {
            "packs": self.packs,
            "active": [[record.rule["id"], record.semantics]
                       for record in self.records],
            "disabled": [[record.rule["id"], record.semantics]
                         for record in self.disabled],
        }
        encoded = json.dumps(identity, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def coverage(self, language: str | None = None, *,
                 rule_languages=frozenset()) -> dict:
        applicable, inapplicable = [], []
        for record in self.records:
            langs = set(record.rule.get("langs", ()))
            applies = (language is None or not langs or "regex" in langs
                       or bool(langs & set(rule_languages)))
            (applicable if applies else inapplicable).append(record)
        return {
            "catalog_version": self.catalog_version(),
            "active": len(applicable),
            "disabled": len(self.disabled),
            "duplicates_removed": len(self.duplicates),
            "inapplicable": len(inapplicable),
            "inapplicable_rules": [record.rule["id"] for record in inapplicable],
            "disabled_rules": [record.rule["id"] for record in self.disabled],
            "provenance": list(self.packs),
        }


def canonical_semantics(rule: dict) -> str:
    """Full executable semantics; provenance annotations do not cause collisions."""
    executable = {key: value for key, value in rule.items()
                  if key not in {"upstream", "upstream_version", "disabled", "enabled"}}
    encoded = json.dumps(executable, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def deduplicate_records(records, *, disabled=(), duplicates=(), packs=()) -> RulePack:
    """Collapse only exact ``(canonical ID, semantics)`` duplicates."""
    result = RulePack(disabled=list(disabled), duplicates=list(duplicates),
                      packs=list(packs))
    seen: dict[tuple[str, str], RuleRecord] = {}
    for record in records:
        key = (record.rule["id"], record.semantics)
        if key in seen:
            kept = seen[key]
            result.duplicates.append({
                "id": record.rule["id"], "semantics": record.semantics,
                "kept": kept.origin.to_dict(), "duplicate": record.origin.to_dict()})
            continue
        seen[key] = record
        result.records.append(record)
    return result


def read_rule_pack(path: str | pathlib.Path) -> RulePack:
    path = pathlib.Path(path)
    raw = path.read_bytes()
    document = json.loads(raw)
    metadata = document.get("metadata", {})
    provenance = {
        "pack": path.name,
        "upstream": document.get("upstream", metadata.get("upstream", "semgrep-rules")),
        "version": str(document.get("version", metadata.get("version", "unspecified"))),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    active, disabled = [], []
    for index, rule in enumerate(document.get("rules", [])):
        origin = RuleOrigin(path.name, provenance["upstream"], provenance["version"], index)
        record = RuleRecord(rule, origin, canonical_semantics(rule))
        (disabled if rule.get("disabled") or rule.get("enabled") is False else active).append(record)
    pack = deduplicate_records(active, disabled=disabled, packs=[provenance])
    return pack


def merge_rule_packs(packs) -> RulePack:
    packs = list(packs)
    return deduplicate_records(
        [record for pack in packs for record in pack.records],
        disabled=[record for pack in packs for record in pack.disabled],
        duplicates=[row for pack in packs for row in pack.duplicates],
        packs=[row for pack in packs for row in pack.packs])
