"""Static dependency inventory with honest reachability states.

Installed dependencies are inferred from declared manifests; reachability is
based on observed import edges, not runtime certainty. Missing metadata is
reported as unknown rather than not vulnerable.
"""
from __future__ import annotations
import ast, json, re
from importlib import metadata as importlib_metadata
from pathlib import Path

STATES = ("installed", "reachable", "not_observed", "unknown")


def _requirements(root: Path) -> set[str]:
    names = set()
    for filename in ("requirements.txt", "requirements-dev.txt", "requirements-ci.txt"):
        path = root / filename
        if path.is_file():
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "-")):
                    continue
                match = re.match(r"([A-Za-z0-9_.-]+)", line)
                if match:
                    names.add(re.sub(r"[-_.]+", "-", match.group(1)).lower())
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            import tomllib
            doc = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            for dep in doc.get("project", {}).get("dependencies", []):
                match = re.match(r"([A-Za-z0-9_.-]+)", dep)
                if match: names.add(re.sub(r"[-_.]+", "-", match.group(1)).lower())
        except (ValueError, OSError):
            pass
    return names


def analyze_dependencies(root: str | Path) -> dict:
    root = Path(root).resolve()
    declared = _requirements(root)
    observed = set()
    parse_failures = []
    excluded = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build"}
    for path in sorted(root.rglob("*.py")):
        if excluded.intersection(path.parts): continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as exc:
            parse_failures.append({"file": str(path.relative_to(root)), "reason": type(exc).__name__})
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import): observed.update(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                observed.add(node.module.split(".")[0])
    rows = []
    for name in sorted(declared):
        module = name.replace("-", "_")
        try:
            importlib_metadata.distribution(name)
            installed = True
        except importlib_metadata.PackageNotFoundError:
            installed = False
        observed_import = module in observed or name in {x.replace("_", "-") for x in observed}
        state = "reachable" if installed and observed_import else "installed" if installed else "not_observed" if not observed_import else "unknown"
        rows.append({"name": name, "state": state, "declared": True, "installed_distribution_found": installed,
                     "static_import_observed": observed_import,
                     "evidence": "installed distribution and static import observed" if state == "reachable" else
                     "installed distribution but no static import observed" if state == "installed" else
                     "no static import observed; dynamic imports may exist" if state == "not_observed" else
                     "static import observed but distribution is not installed or cannot be mapped"})
    # Imported external modules not found in manifests are not presumed installed.
    stdlib = set(getattr(__import__("sys"), "stdlib_module_names", ()))
    declared_modules = {n.replace("-", "_") for n in declared}
    for module in sorted(observed - stdlib - declared_modules):
        if module.startswith("_"): continue
        rows.append({"name": module, "state": "unknown", "declared": False, "evidence": "import observed but no matching supported manifest declaration"})
    return {"schema": "pegrex.dependency-reachability.v1", "root": str(root), "dependencies": rows,
            "summary": {state: sum(row["state"] == state for row in rows) for state in STATES},
            "coverage": "partial" if parse_failures else "static-only", "parse_failures": parse_failures,
            "limitations": ["manifest declaration does not prove installed runtime state", "static imports miss reflection and dynamic loading", "not_observed is not proof of unreachable", "dynamic imports may exist even when no static import was observed"]}
