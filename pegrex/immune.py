"""Repository immune system: compare repository state with declared boundaries.

Findings are policy deviations, not proofs that a program is malicious. Parse or
inventory gaps are surfaced as UNKNOWN instead of being treated as clean.
"""
from __future__ import annotations
import hashlib, json
from pathlib import Path
from .repository import RepositoryIndex

SCHEMA = "pegrex.repository-immune.v1"

def _digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

def audit_repository(root, *, boundaries=None, invariants=None, baseline=None, configuration=None):
    """Audit changed repository state against explicit boundary/invariant rules.

    boundaries maps module/path prefixes to allowed import prefixes, e.g.
    {"pegrex.security": ["pegrex.core", "pegrex.policy"]}.
    invariants is a list of {id, path, contains|not_contains}; baseline is an
    optional prior report whose stable finding IDs can be compared.
    """
    root = Path(root).resolve()
    boundaries = boundaries or {}
    invariants = invariants or []
    findings, unknowns, inventory = [], [], []
    for path in sorted(root.rglob("*.py")):
        if any(part in {".git", ".venv", "venv", "__pycache__"} for part in path.parts):
            continue
        try:
            rel = path.relative_to(root).as_posix()
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            unknowns.append({"path": str(path.relative_to(root)), "reason": type(exc).__name__})
            continue
        inventory.append({"path": rel, "sha256": hashlib.sha256(text.encode()).hexdigest()})
        # Import boundary checks are deliberately syntactic and fail closed on unparseable files.
        try:
            import ast
            tree = ast.parse(text, filename=rel)
        except SyntaxError:
            unknowns.append({"path": rel, "reason": "parse-error"})
            continue
        module = rel[:-3].replace("/", ".")
        for prefix, allowed in boundaries.items():
            if module == prefix or module.startswith(prefix + "."):
                for node in ast.walk(tree):
                    imported = []
                    if isinstance(node, ast.Import):
                        imported = [a.name for a in node.names]
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        imported = [node.module]
                    for target in imported:
                        if target.startswith("."):
                            continue
                        if not any(target == a or target.startswith(a + ".") for a in allowed):
                            fid = _digest(["boundary", rel, target, prefix])
                            findings.append({"id": fid, "kind": "architecture-boundary", "path": rel,
                                             "line": getattr(node, "lineno", 1), "source_module": module,
                                             "import": target, "boundary": prefix, "allowed": list(allowed)})
        for rule in invariants:
            rid, rule_path = rule.get("id"), rule.get("path")
            if not rid or not rule_path or Path(rule_path).as_posix() != rel:
                continue
            if "contains" in rule and rule["contains"] not in text:
                findings.append({"id": _digest(["invariant", rid, rel]), "kind": "invariant-violation",
                                 "rule": rid, "path": rel, "message": "required marker absent"})
            if "not_contains" in rule and rule["not_contains"] in text:
                findings.append({"id": _digest(["invariant", rid, rel]), "kind": "invariant-violation",
                                 "rule": rid, "path": rel, "message": "forbidden marker present"})
    previous = {f.get("id") for f in (baseline or {}).get("findings", [])}
    for finding in findings:
        finding["new_since_baseline"] = finding["id"] not in previous
    status = "unknown" if unknowns else ("findings" if findings else "clean-under-configured-rules")
    return {"schema": SCHEMA, "status": status, "root_fingerprint": _digest(inventory),
            "files": len(inventory), "findings": findings, "unknowns": unknowns,
            "rules_configured": len(boundaries) + len(invariants)}
