"""Fail-closed security profiles for UNKNOWNs and verification outcomes."""
from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass, asdict

SCHEMA = "pegrex.security-policy-decision.v1"


@dataclass(frozen=True)
class SecurityProfile:
    """Declare which incomplete results deny an operation.

    ``fail_on_unknown=True`` with empty selectors denies every UNKNOWN.
    Selectors narrow that default to matching reasons/categories/rules. Explicit
    allowances remain visible in the decision and never become clean evidence.
    """

    name: str = "fail-closed"
    fail_on_unknown: bool = True
    unknown_reasons: tuple[str, ...] = ()
    unknown_categories: tuple[str, ...] = ()
    unknown_rules: tuple[str, ...] = ()
    allow_unknown_reasons: tuple[str, ...] = ()
    require_proved: bool = True

    def identity(self) -> str:
        """Implement identity with the module's explicit API and failure semantics."""
        payload = json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode()).hexdigest()

    @classmethod
    def from_dict(cls, value: dict) -> "SecurityProfile":
        """Implement from dict with the module's explicit API and failure semantics."""
        fields = cls.__dataclass_fields__
        normalized = {key: tuple(item) if key.endswith(("reasons", "categories", "rules")) and isinstance(item, list) else item
                      for key, item in value.items() if key in fields}
        return cls(**normalized)

    def to_dict(self) -> dict:
        """Implement to dict with the module's explicit API and failure semantics."""
        row = asdict(self)
        row["profile_sha256"] = self.identity()
        return row


def _unknown_rows(report: dict) -> list[dict]:
    rows = []
    for index, row in enumerate(report.get("unknowns") or []):
        if isinstance(row, str):
            rows.append({"reason": row, "kind": "unknown", "index": index})
        elif isinstance(row, dict):
            rows.append({**row, "kind": row.get("kind", "unknown"), "index": index})
        else:
            rows.append({"reason": repr(row), "kind": "unknown", "index": index})
    for index, row in enumerate(report.get("findings") or []):
        if isinstance(row, dict) and row.get("kind") == "unknown":
            rows.append({**row, "reason": row.get("reason") or row.get("message", "scanner-unknown"),
                         "index": index})
    if report.get("verdict") == "unknown" and not rows:
        rows.append({"reason": report.get("reason", "verdict-unknown"), "kind": "unknown"})
    if report.get("status") in {"unknown", "partial"} and not rows:
        rows.append({"reason": f"status-{report['status']}", "kind": "unknown"})
    return rows


def _matches(row: dict, patterns: tuple[str, ...], *keys: str) -> bool:
    if not patterns:
        return False
    values = [str(row.get(key, "")) for key in keys]
    return any(fnmatch.fnmatchcase(value, pattern)
               for pattern in patterns for value in values)


def evaluate_security_policy(report: dict, profile: SecurityProfile | None = None) -> dict:
    """Implement evaluate security policy with the module's explicit API and failure semantics."""
    profile = profile or SecurityProfile()
    failures, accepted = [], []
    for row in _unknown_rows(report):
        allowed = _matches(row, profile.allow_unknown_reasons, "reason")
        selected = not profile.fail_on_unknown
        if profile.fail_on_unknown:
            selected = not (profile.unknown_reasons or profile.unknown_categories or profile.unknown_rules)
            selected = selected or _matches(row, profile.unknown_reasons, "reason")
            selected = selected or _matches(row, profile.unknown_categories, "category", "kind", "resource")
            selected = selected or _matches(row, profile.unknown_rules, "rule_id", "id")
        if selected and not allowed:
            failures.append({"type": "policy-unknown", "evidence": row})
        else:
            accepted.append(row)
    if profile.require_proved:
        verdict = report.get("verdict")
        if verdict is None and "verified" in report:
            verdict = "proved" if report["verified"] is True else (
                "refuted" if report.get("counterexample") else "unknown")
        if verdict is not None and verdict != "proved":
            failures.append({"type": "proof-not-preserved", "verdict": verdict,
                             "counterexample": report.get("counterexample"),
                             "reason": report.get("reason") or report.get("note")})
    return {"schema": SCHEMA, "allowed": not failures, "profile": profile.to_dict(),
            "failures": failures, "accepted_unknowns": accepted,
            "unknown_count": len(failures) + len(accepted)}


def require_policy(report: dict, profile: SecurityProfile | None = None) -> dict:
    """Implement require policy with the module's explicit API and failure semantics."""
    decision = evaluate_security_policy(report, profile)
    if not decision["allowed"]:
        raise PermissionError("security profile denied operation: " +
                              "; ".join(row["type"] for row in decision["failures"]))
    return decision
