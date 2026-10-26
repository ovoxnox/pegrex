"""Concurrency evidence: shared-state interference, races, locks, and ordering.

Findings are possible defects with evidence, not claims of a concrete race or
deadlock witness. Unsupported alias, happens-before, and memory-model cases
remain explicit coverage UNKNOWNs.
"""
from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass

from .languages import normalize_language

SCHEMA = "pegrex.concurrency-analysis.v1"


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


@dataclass(frozen=True)
class Access:
    name: str
    mode: str
    line: int
    locks: frozenset[str]


class _BodyCollector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.accesses: list[Access] = []
        self.calls: set[str] = set()
        self.orders: list[tuple[str, str, int]] = []
        self.lock_stack: list[str] = []
        self.explicit_shared: set[str] = set()

    def visit_Global(self, node: ast.Global) -> None:
        """Implement visit Global with the module's explicit API and failure semantics."""
        self.explicit_shared.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        """Implement visit Nonlocal with the module's explicit API and failure semantics."""
        self.explicit_shared.update(node.names)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Implement visit FunctionDef with the module's explicit API and failure semantics."""
        return

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Implement visit AsyncFunctionDef with the module's explicit API and failure semantics."""
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Implement visit ClassDef with the module's explicit API and failure semantics."""
        return

    def visit_Name(self, node: ast.Name) -> None:
        """Implement visit Name with the module's explicit API and failure semantics."""
        if not node.id.startswith("__"):
            self.accesses.append(Access(node.id,
                                        "write" if isinstance(node.ctx, (ast.Store, ast.Del)) else "read",
                                        node.lineno, frozenset(self.lock_stack)))

    def visit_Call(self, node: ast.Call) -> None:
        """Implement visit Call with the module's explicit API and failure semantics."""
        name = _name(node.func)
        if name:
            self.calls.add(name.rsplit(".", 1)[-1])
        self.generic_visit(node)

    def _locks(self, items) -> list[str]:
        result = []
        for item in items:
            name = _name(item.context_expr)
            if name.endswith(".acquire"):
                name = name[:-8]
            result.append(name or ast.unparse(item.context_expr))
        return result

    def _with(self, node, items) -> None:
        locks = self._locks(items)
        for lock in locks:
            for outer in self.lock_stack:
                self.orders.append((outer, lock, node.lineno))
            self.lock_stack.append(lock)
        for statement in node.body:
            self.visit(statement)
        del self.lock_stack[-len(locks):]

    def visit_With(self, node: ast.With) -> None:
        """Implement visit With with the module's explicit API and failure semantics."""
        self._with(node, node.items)

    def visit_AsyncWith(self, node: ast.AsyncWith) -> None:
        """Implement visit AsyncWith with the module's explicit API and failure semantics."""
        self._with(node, node.items)


def _python_functions(tree: ast.Module) -> dict[str, dict]:
    functions: dict[str, dict] = {}

    def visit(body, prefix=""):
        """Implement visit with the module's explicit API and failure semantics."""
        for node in body:
            if isinstance(node, ast.ClassDef):
                visit(node.body, prefix + node.name + ".")
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                collector = _BodyCollector()
                for statement in node.body:
                    collector.visit(statement)
                name = prefix + node.name
                functions[name] = {"accesses": collector.accesses,
                                   "calls": collector.calls,
                                   "orders": collector.orders,
                                   "shared_names": collector.explicit_shared,
                                   "line": node.lineno}
                visit(node.body, name + ".")
    visit(tree.body)
    return functions


def _thread_targets(tree: ast.Module) -> list[dict]:
    targets: list[dict] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = _name(node.func)
        target = None
        mechanism = name
        if name == "threading.Thread":
            for keyword in node.keywords:
                if keyword.arg == "target":
                    target = _name(keyword.value)
        elif name.endswith(".submit") and node.args:
            target = _name(node.args[0])
        elif name in {"asyncio.create_task", "asyncio.ensure_future"} and node.args:
            if isinstance(node.args[0], ast.Call):
                target = _name(node.args[0].func)
        if target:
            targets.append({"function": target.rsplit(".", 1)[-1], "line": node.lineno,
                            "mechanism": mechanism})
    return targets


def _reachable(targets: list[dict], functions: dict[str, dict]) -> tuple[set[str], list[str]]:
    short = {name.rsplit(".", 1)[-1]: name for name in functions}
    reached: set[str] = set()
    pending = [target["function"] for target in targets]
    missing: set[str] = set()
    while pending:
        name = pending.pop()
        full = name if name in functions else short.get(name)
        if full is None:
            missing.add(name)
            continue
        if full in reached:
            continue
        reached.add(full)
        pending.extend(functions[full]["calls"])
    return reached, sorted(missing)


def _cycles(orders: list[tuple[str, str, int]]) -> list[list[str]]:
    graph: dict[str, set[str]] = {}
    for before, after, _ in orders:
        graph.setdefault(before, set()).add(after)
    cycles = set()

    def dfs(start, current, path):
        """Implement dfs with the module's explicit API and failure semantics."""
        for successor in sorted(graph.get(current, ())):
            if successor == start:
                cycles.add(tuple(path + [start]))
            elif successor not in path and len(path) < 8:
                dfs(start, successor, path + [successor])
    for node in sorted(graph):
        dfs(node, node, [node])
    return [list(cycle) for cycle in sorted(cycles)]



def _happens_before(tree: ast.Module) -> dict:
    """Extract explicit Python task/edge evidence without claiming full HB."""
    aliases = {}
    tasks = []
    edges = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            if len(targets) == 1 and isinstance(targets[0], ast.Name) and isinstance(value, ast.Call):
                name = _name(value.func)
                target = None
                if name == "threading.Thread":
                    target = next((_name(k.value) for k in value.keywords if k.arg == "target"), None)
                elif name in {"asyncio.create_task", "asyncio.ensure_future"} and value.args and isinstance(value.args[0], ast.Call):
                    target = _name(value.args[0].func)
                elif name.endswith(".submit") and value.args:
                    target = _name(value.args[0])
                if target:
                    aliases[targets[0].id] = {"function": target, "created": node.lineno}
                    if name != "threading.Thread":
                        tasks.append({"task": targets[0].id, "function": target,
                                      "start_line": node.lineno, "mechanism": name})
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _name(node.func)
            if "." not in name:
                continue
            owner, operation = name.rsplit(".", 1)
            if owner not in aliases:
                continue
            task = aliases[owner]
            if operation == "start":
                tasks.append({"task": owner, "function": task["function"],
                              "start_line": node.lineno, "mechanism": "thread.start"})
                edges.append({"kind": "thread-start", "before": node.lineno,
                              "after": task["function"], "line": node.lineno})
            elif operation in {"join", "result"}:
                edges.append({"kind": "thread-join" if operation == "join" else "future-result",
                              "before": task["function"], "after": node.lineno,
                              "line": node.lineno})
        elif isinstance(node, ast.Await) and isinstance(node.value, ast.Name) and node.value.id in aliases:
            edges.append({"kind": "async-await", "before": aliases[node.value.id]["function"],
                          "after": node.lineno, "line": node.lineno})
    return {"tasks": sorted(tasks, key=lambda row: (row["start_line"], row["task"])),
            "edges": sorted(edges, key=lambda row: (row["line"], row["kind"]))}

def _analyze_python(source: str) -> dict:
    tree = ast.parse(source)
    functions = _python_functions(tree)
    targets = _thread_targets(tree)
    reached, missing = _reachable(targets, functions)
    orders = [order for name in reached for order in functions[name]["orders"]]
    findings: list[dict] = []
    unknowns = [f"unresolved thread target or callee: {name}" for name in missing]
    shared: dict[str, list[dict]] = {}
    module_names = {target.id for node in tree.body
                    if isinstance(node, (ast.Assign, ast.AnnAssign))
                    for target in ((node.targets if isinstance(node, ast.Assign) else [node.target]))
                    if isinstance(target, ast.Name)}
    shared_names = set(module_names)
    for name in reached:
        shared_names.update(functions[name]["shared_names"])
    for name in sorted(reached):
        for access in functions[name]["accesses"]:
            if access.name not in shared_names:
                continue
            shared.setdefault(access.name, []).append({
                "function": name, "mode": access.mode, "line": access.line,
                "locks": sorted(access.locks),
            })
    for variable, accesses in sorted(shared.items()):
        if not any(row["mode"] == "write" for row in accesses):
            continue
        if len(accesses) < 2 and not targets:
            continue
        evidence = {"variable": variable, "accesses": accesses}
        findings.append({"kind": "interference", "verdict": "possible",
                         "confidence": "medium", "evidence": evidence,
                         "message": f"shared-state accesses to {variable} in concurrent targets"})
        common_locks = set(accesses[0]["locks"])
        for access in accesses[1:]:
            common_locks &= set(access["locks"])
        if not common_locks:
            findings.append({"kind": "race", "verdict": "possible",
                             "confidence": "medium", "evidence": evidence,
                             "message": f"possible data race on {variable}: write access without a common lock"})
    for cycle in _cycles(orders):
        findings.append({"kind": "deadlock", "verdict": "possible",
                         "confidence": "high",
                         "evidence": {"lock_cycle": cycle,
                                      "orders": [list(order) for order in orders]},
                         "message": "inconsistent nested lock acquisition order: " + " -> ".join(cycle)})
    if targets:
        unknowns.append("thread aliasing and external synchronization are approximated")
    return targets, findings, unknowns, shared, orders


def _analyze_memory_ordering(source: str) -> tuple[list[dict], list[str]]:
    findings: list[dict] = []
    unknowns: list[str] = []
    lines = source.splitlines()
    for number, line in enumerate(lines, 1):
        if "memory_order_relaxed" in line:
            findings.append({"kind": "memory-ordering", "verdict": "possible",
                             "confidence": "medium",
                             "evidence": {"line": number, "text": line.strip(),
                                          "property": "relaxed-atomic"},
                             "message": "relaxed atomic does not itself establish inter-thread happens-before"})
    if re.search(r"std::thread|pthread_create|#pragma\s+omp", source):
        unknowns.append("native thread alias and full happens-before coverage is partial")
    return findings, unknowns


def analyze_concurrency(source: str, language: str = "python") -> dict:
    """Implement analyze concurrency with the module's explicit API and failure semantics."""
    resolved = normalize_language(language)
    if resolved == "python":
        tree = ast.parse(source)
        targets, findings, unknowns, shared, orders = _analyze_python(source)
        ordering: list[dict] = []
    elif resolved in {"c", "cpp", "rust"}:
        targets, shared, orders = [], {}, []
        findings, unknowns = _analyze_memory_ordering(source)
        ordering = list(findings)
        if resolved == "rust" and "unsafe" not in source and "thread" not in source:
            unknowns.append("Rust thread alias coverage is not modeled")
    else:
        raise NotImplementedError(f"concurrency analysis unsupported for {resolved}; coverage unknown")
    report = {
        "schema": SCHEMA,
        "language": resolved,
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        "status": "unknown" if unknowns else "ok",
        "threads": targets,
        "shared_state": shared,
        "lock_orders": [list(order) for order in orders],
        "memory_ordering": ordering,
        "happens_before": _happens_before(tree) if resolved == "python" else {"tasks": [], "edges": []},
        "findings": findings,
        "unknowns": sorted(set(unknowns)),
        "coverage": {"races": "heuristic-possible", "deadlocks": "lock-order-cycles",
                     "interference": "reachable-thread-functions",
                     "memory_ordering": "selected-atomic-properties",
                     "happens_before": "explicit start/join/result/await edges; alias coverage partial"},
    }
    return report
