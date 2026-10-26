"""Mutation testing with semantic confirmation and isolated argv execution."""
from __future__ import annotations

import ast
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

SCHEMA = "pegrex.mutation-testing.v1"
_IGNORE = {".git", ".hg", ".svn", ".pegrex-cache", "__pycache__",
           "node_modules", "dist", "build", ".venv", "venv"}


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _location(node) -> tuple:
    return (type(node).__name__, node.lineno, node.col_offset)


def generate_mutants(source: str, *, max_mutants: int = 100) -> list[dict]:
    """Generate deterministic single-site Python behavior-mutation candidates."""
    tree = ast.parse(source)
    sites = []
    comparisons = {ast.Lt: ast.LtE, ast.LtE: ast.Lt, ast.Gt: ast.GtE,
                   ast.GtE: ast.Gt, ast.Eq: ast.NotEq, ast.NotEq: ast.Eq}
    binaries = {ast.Add: ast.Sub, ast.Sub: ast.Add,
                ast.Mult: ast.Div, ast.Div: ast.Mult}
    for node in ast.walk(tree):
        if isinstance(node, ast.Compare) and len(node.ops) == 1:
            replacement = comparisons.get(type(node.ops[0]))
            if replacement:
                sites.append(("comparison", _location(node), replacement,
                              f"{type(node.ops[0]).__name__} -> {replacement.__name__}"))
        elif isinstance(node, ast.BinOp) and type(node.op) in binaries:
            replacement = binaries[type(node.op)]
            sites.append(("binary", _location(node), replacement,
                          f"{type(node.op).__name__} -> {replacement.__name__}"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, int) and not isinstance(node.value, bool):
            sites.append(("constant", _location(node), node.value + 1,
                          f"integer constant {node.value} -> {node.value + 1}"))
    sites.sort(key=lambda row: (row[1][1], row[1][2], row[0], row[3]))
    mutants = []
    for kind, location, replacement, description in sites[:max_mutants]:
        class Replace(ast.NodeTransformer):
            def visit_Compare(self, node):
                """Implement visit Compare with the module's explicit API and failure semantics."""
                self.generic_visit(node)
                if kind == "comparison" and _location(node) == location:
                    node.ops = [replacement()]
                return node

            def visit_BinOp(self, node):
                """Implement visit BinOp with the module's explicit API and failure semantics."""
                self.generic_visit(node)
                if kind == "binary" and _location(node) == location:
                    node.op = replacement()
                return node

            def visit_Constant(self, node):
                """Implement visit Constant with the module's explicit API and failure semantics."""
                if kind == "constant" and _location(node) == location:
                    return ast.copy_location(ast.Constant(value=replacement), node)
                return node

        mutant_tree = Replace().visit(ast.parse(source))
        ast.fix_missing_locations(mutant_tree)
        mutated = ast.unparse(mutant_tree) + "\n"
        identity = _digest(description + "\0" + mutated)
        mutants.append({"id": identity[:20], "kind": kind,
                        "line": location[1], "column": location[2],
                        "description": description, "source": mutated,
                        "source_sha256": _digest(source), "mutant_sha256": _digest(mutated)})
    return mutants


def _run(command, cwd: Path, timeout_ms: int, env: dict) -> dict:
    try:
        completed = subprocess.run(list(command), cwd=cwd, env=env, shell=False,
                                   capture_output=True, text=True,
                                   timeout=timeout_ms / 1000)
        return {"returncode": completed.returncode,
                "stdout": completed.stdout[-4000:], "stderr": completed.stderr[-4000:],
                "timed_out": False}
    except subprocess.TimeoutExpired as exc:
        return {"returncode": None, "stdout": str(exc.stdout or "")[-1000:],
                "stderr": str(exc.stderr or "")[-1000:], "timed_out": True}


def mutation_test(project_root: str | Path, target: str | Path, *,
                  test_command=(sys.executable, "-m", "pytest", "-q"),
                  timeout_ms: int = 30_000, max_mutants: int = 30) -> dict:
    """Run tests against confirmed mutants in a disposable project copy."""
    root = Path(project_root).resolve()
    target_path = Path(target)
    if not target_path.is_absolute():
        target_path = root / target_path
    target_path = target_path.resolve()
    relative = target_path.relative_to(root)
    original = target_path.read_text(encoding="utf-8")
    candidates = generate_mutants(original, max_mutants=max_mutants)
    results, unknowns = [], []
    with tempfile.TemporaryDirectory(prefix="pegrex-mutation-") as workspace:
        baseline = Path(workspace) / "baseline"
        shutil.copytree(root, baseline, ignore=shutil.ignore_patterns(*_IGNORE))
        env = dict(os.environ)
        env["PYTHONPATH"] = str(baseline) + os.pathsep + env.get("PYTHONPATH", "")
        base_run = _run(test_command, baseline, timeout_ms, env)
        if base_run["timed_out"] or base_run["returncode"] != 0:
            return {"schema": SCHEMA, "status": "unknown", "mutation_score": None,
                    "baseline": base_run, "mutants": [],
                    "unknowns": ["baseline test suite did not pass; mutation results are invalid"]}
        for candidate in candidates:
            row = {key: value for key, value in candidate.items() if key != "source"}
            with tempfile.TemporaryDirectory(prefix="pegrex-mutant-check-") as check:
                before = Path(check) / "before.py"
                after = Path(check) / "after.py"
                before.write_text(original, encoding="utf-8")
                after.write_text(candidate["source"], encoding="utf-8")
                from .semantics import verify_patch
                verdict = verify_patch(str(before), str(after))
            if verdict["verified"]:
                results.append({**row, "status": "equivalent", "evidence": verdict})
                continue
            witness = verdict.get("counterexample")
            if not witness or witness.get("confirmed") is not True:
                results.append({**row, "status": "unknown", "evidence": verdict})
                unknowns.append(f"{candidate['id']}: behavior change not confirmed")
                continue
            mutant_root = Path(workspace) / ("mutant-" + candidate["id"])
            shutil.copytree(baseline, mutant_root)
            (mutant_root / relative).write_text(candidate["source"], encoding="utf-8")
            mutant_env = dict(env, PYTHONPATH=str(mutant_root) + os.pathsep + env.get("PYTHONPATH", ""))
            execution = _run(test_command, mutant_root, timeout_ms, mutant_env)
            if execution["timed_out"]:
                status = "unknown"
                unknowns.append(f"{candidate['id']}: mutant test execution timed out")
            else:
                status = "survived" if execution["returncode"] == 0 else "killed"
            results.append({**row, "status": status,
                            "counterexample": witness, "execution": execution})
            shutil.rmtree(mutant_root)
    scored = [row for row in results if row["status"] in {"killed", "survived"}]
    killed = sum(row["status"] == "killed" for row in scored)
    return {
        "schema": SCHEMA, "status": "partial" if unknowns else "complete",
        "target": relative.as_posix(), "source_sha256": _digest(original),
        "generated": len(candidates), "scored": len(scored), "killed": killed,
        "survived": len(scored) - killed,
        "equivalent": sum(row["status"] == "equivalent" for row in results),
        "mutation_score": killed / len(scored) if scored else None,
        "baseline": base_run, "mutants": results, "unknowns": unknowns,
    }
