"""Reachability-aware dependency vulnerability evidence (not absence proof)."""
from __future__ import annotations
import ast, hashlib
from pathlib import Path
from .sca import scan
SCHEMA = "pegrex.reachability-sca.v1"


def _python_usage(root):
    root = Path(root); usages, functions, unknowns = {}, {}, []
    for path in sorted(root.rglob("*.py")):
        if any(part in {".git", "__pycache__", "venv", ".venv"} for part in path.parts): continue
        module = ".".join(path.relative_to(root).with_suffix("").parts)
        try: tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeError) as error:
            unknowns.append(f"{path}: {error}"); continue
        imports = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names: imports[alias.asname or alias.name.split(".")[0]] = alias.name
            elif isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names: imports[alias.asname or alias.name] = node.module + "." + alias.name
        def dotted(node):
            """Implement dotted with the module's explicit API and failure semantics."""
            parts = []
            while isinstance(node, ast.Attribute): parts.append(node.attr); node = node.value
            if isinstance(node, ast.Name): parts.append(node.id)
            return ".".join(reversed(parts))
        def visit(body, owner):
            """Implement visit with the module's explicit API and failure semantics."""
            calls = []
            for node in ast.walk(ast.Module(body=body, type_ignores=[])):
                if isinstance(node, ast.Call):
                    raw = dotted(node.func); full = imports.get(raw.split(".")[0], raw.split(".")[0]) + ("." + ".".join(raw.split(".")[1:]) if "." in raw else "")
                    calls.append((full, path, getattr(node, "lineno", 1)))
                    package = full.split(".")[0]
                    usages.setdefault(package, []).append({"symbol": full, "file": str(path),
                        "line": node.lineno, "function": owner, "reachable": owner == module + ".$module"})
            functions[owner] = calls
        visit(tree.body, module + ".$module")
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(node.body, module + "." + node.name)
            importsites = []
        for name, target in imports.items():
            usages.setdefault(target.split(".")[0], []).append({"symbol": target, "file": str(path),
                "line": 1, "function": module + ".$module", "reachable": True, "import": True})
    reachable = {owner for owner in functions if owner.endswith(".$module")}
    changed = True
    while changed:
        changed = False
        for owner in sorted(reachable):
            for symbol, _path, _line in functions.get(owner, []):
                for callee in functions:
                    if callee not in reachable and (callee == symbol or callee.endswith("." + symbol)):
                        reachable.add(callee); changed = True
    for sites in usages.values():
        for site in sites:
            site["reachable"] = site.get("function") in reachable
    return usages, unknowns


def scan_reachable(lockfile, source_root, *, vulnerable_calls=None, offline=False,
                   snapshot=None, cache_path=None) -> dict:
    """Add repository call evidence while retaining the underlying OSV UNKNOWNs."""
    base = scan(str(lockfile), offline=offline, snapshot=snapshot, cache_path=cache_path)
    usages, unknowns = _python_usage(Path(source_root))
    mapping = vulnerable_calls or {}
    findings = []
    for vulnerability in base["vulnerabilities"]:
        package = vulnerability["name"].replace("-", "_").split(".")[0]
        sites = usages.get(package, [])
        symbols = (mapping.get(vulnerability["id"]) or mapping.get(vulnerability["name"])
                   or vulnerability.get("affected_functions") or vulnerability.get("symbols"))
        matches = [] if not symbols else [site for site in sites if site.get("symbol") in symbols]
        reachable = [site for site in matches if site.get("reachable")]
        if reachable:
            status, reason = "reachable", "reachable static call to a declared vulnerable symbol"
        elif not symbols:
            status, reason = "unknown", "vulnerable symbol information unavailable; import alone is not vulnerable-call reachability"
        elif unknowns:
            status, reason = "unknown", "repository coverage incomplete"
        else:
            status, reason = "not-observed", "no reachable declared vulnerable call observed in scanned Python source; not a proof of absence"
        findings.append({**vulnerability, "installed": True, "reachability": status,
                         "reachability_reason": reason, "call_sites": matches,
                         "dependency_import_observed": bool(sites),
                         "evidence_strength": "static-call-graph" if reachable else "incomplete-or-negative-observation"})
    return {"schema": SCHEMA, "schema_version": 1,
            "verdict": "unknown" if base["unknowns"] or unknowns or any(row["reachability"] == "unknown" for row in findings) else "ok",
            "inventory": base, "findings": findings,
            "unknowns": base["unknowns"] + [{"source": str(source_root), "reason": row} for row in unknowns],
            "scope": "installed inventory plus static Python call reachability; dynamic and external callers are not exhaustively modeled"}
