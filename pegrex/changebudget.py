"""Structured semantic change budgets for repository pull requests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .cognitive import cognitive_complexity
from .flow import analyze_repository
from .repomemory import RepositoryMemory
from .semantics import explain_patch

SCHEMA = "pegrex.semantic-change-budget.v1"
_LOCKS = ("package-lock.json", "Cargo.lock", "requirements.txt", "requirements-ci.txt",
          "pyproject.toml", "poetry.lock", "Pipfile.lock", "go.mod", "go.sum")


def _digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _finding_id(row):
    return json.dumps({key: row.get(key) for key in (
        "id", "file", "line", "function", "rule", "sink", "matched_ast")},
        sort_keys=True, separators=(",", ":"), default=str)


def _source_files(root):
    return {path.relative_to(root).as_posix(): path for path in root.rglob("*")
            if path.is_file() and ".git" not in path.parts and "__pycache__" not in path.parts}


def _dependency_changes(before_files, after_files):
    rows = []
    for name in _LOCKS:
        keys = sorted({key for key in before_files if Path(key).name == name} |
                      {key for key in after_files if Path(key).name == name})
        for key in keys:
            before, after = before_files.get(key), after_files.get(key)
            old_hash = _digest(before) if before else None
            new_hash = _digest(after) if after else None
            if old_hash != new_hash:
                rows.append({"file": key, "change": "modified" if before and after else
                             "removed" if before else "added", "before_sha256": old_hash,
                             "after_sha256": new_hash})
    return sorted(rows, key=lambda row: row["file"])


def summarize_semantic_change(before_root, after_root, *, budget=None) -> dict:
    """Summarize a PR without treating incomplete regions as unchanged."""
    before_root, after_root = Path(before_root).resolve(), Path(after_root).resolve()
    unknowns = []
    try:
        before = RepositoryMemory(before_root); before.refresh()
        after = RepositoryMemory(after_root); after.refresh()
        unknowns.extend("before:" + row for row in before.limitations)
        unknowns.extend("after:" + row for row in after.limitations)
        public = []
        explanations = {}
        for key in sorted(set(before.apis) | set(after.apis)):
            old, new = before.apis.get(key), after.apis.get(key)
            if old == new:
                continue
            row = {"api": key, "change": "modified" if old and new else "removed" if old else "added",
                   "before_identity": old and old["api_identity"],
                   "after_identity": new and new["api_identity"], "verdict": "unknown"}
            if old and new and old["path"] == new["path"]:
                path = old["path"]
                if path not in explanations:
                    try:
                        explanations[path] = explain_patch(str(before_root / path), str(after_root / path))
                    except Exception as error:
                        explanations[path] = {"verdict": "unknown", "unknowns": [str(error)], "changes": []}
                evidence = explanations[path]
                row.update(verdict=evidence["verdict"], semantic_evidence=evidence)
                unknowns.extend(f"public-contract:{key}:{reason}" for reason in evidence["unknowns"])
            else:
                unknowns.append(f"public-contract:{key}:addition/removal requires review")
            public.append(row)

        before_flow = analyze_repository(before_root)
        after_flow = analyze_repository(after_root)
        old_findings = {_finding_id(row): row for row in before_flow["findings"]}
        new_findings = {_finding_id(row): row for row in after_flow["findings"]}
        security = [{"change": "removed", "finding": old_findings[key]} for key in sorted(old_findings.keys() - new_findings.keys())]
        security += [{"change": "added", "finding": new_findings[key]} for key in sorted(new_findings.keys() - old_findings.keys())]
        for label, report in (("before", before_flow), ("after", after_flow)):
            unknowns.extend(f"security:{label}:{row}" for row in report.get("unknowns", []))

        before_files, after_files = _source_files(before_root), _source_files(after_root)
        dependencies = _dependency_changes(before_files, after_files)
        complexity, complexity_increase = [], 0
        for key in sorted(set(before_files) | set(after_files)):
            if not key.endswith(".py") or key not in before_files or key not in after_files:
                continue
            if _digest(before_files[key]) == _digest(after_files[key]):
                continue
            try:
                old = cognitive_complexity(before_files[key].read_text(encoding="utf-8"), lang="python")
                new = cognitive_complexity(after_files[key].read_text(encoding="utf-8"), lang="python")
                if old["verdict"] != "ok" or new["verdict"] != "ok":
                    unknowns.append(f"complexity:{key}:analysis incomplete")
                    complexity.append({"file": key, "verdict": "unknown"})
                    continue
                old_functions = {row["name"]: row for row in old["functions"]}
                new_functions = {row["name"]: row for row in new["functions"]}
                names = set(old_functions) | set(new_functions)
                for name in sorted(names):
                    old_score = (old_functions.get(name) or {}).get("complexity")
                    new_score = (new_functions.get(name) or {}).get("complexity")
                    if old_score != new_score:
                        delta = (new_score or 0) - (old_score or 0)
                        complexity_increase += max(0, delta)
                        complexity.append({"file": key, "function": name,
                            "before": old_score, "after": new_score, "delta": delta})
            except Exception as error:
                unknowns.append(f"complexity:{key}:{type(error).__name__}: {error}")
        metrics = {"public_contract_changes": len(public),
                   "security_surface_changes": len(security),
                   "dependency_changes": len(dependencies),
                   "complexity_increase": complexity_increase,
                   "unknown_regions": len(set(unknowns))}
        limits = {key: budget[key] for key in metrics if budget and key in budget}
        exceeded = []
        for key, limit in limits.items():
            if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
                unknowns.append(f"budget:{key}:limit must be a nonnegative integer")
            elif metrics[key] > limit:
                exceeded.append({"metric": key, "actual": metrics[key], "limit": limit})
        unknowns = sorted(set(unknowns))
        metrics["unknown_regions"] = len(unknowns)
        verdict = "refuted" if exceeded else "unknown" if unknowns else "proved"
        return {"schema": SCHEMA, "schema_version": 1, "verdict": verdict,
                "status": "unknown" if unknowns else "complete",
                "public_contract_changes": public, "security_surface_changes": security,
                "dependency_changes": dependencies, "complexity_changes": complexity,
                "unknown_regions": unknowns, "metrics": metrics, "budget": limits,
                "budget_exceeded": exceeded,
                "before_memory_identity": before.memory_identity,
                "after_memory_identity": after.memory_identity,
                "scope": "structured change accounting; PROVED means complete within analyzer scope, not safe to merge"}
    except Exception as error:
        return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown",
                "status": "unknown", "unknown_regions": [f"change summary failed: {type(error).__name__}: {error}"],
                "public_contract_changes": [], "security_surface_changes": [],
                "dependency_changes": [], "complexity_changes": []}
