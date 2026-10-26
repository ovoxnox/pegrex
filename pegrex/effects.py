"""Explicit, evidence-bearing side-effect inference for Python sources.

Effects describe possible operations, not proof that an operation executes on
every path. Local mutation and externally visible mutation are distinguished;
unknown languages are refused rather than reported as effect-free.
"""
from __future__ import annotations

import ast
import hashlib
from dataclasses import dataclass
from typing import Iterable

SCHEMA = "pegrex.effects.v1"
CATEGORIES = ("io", "filesystem", "network", "process", "exception",
              "mutation", "nondeterminism", "concurrency")


@dataclass(frozen=True)
class Effect:
    category: str
    action: str
    line: int
    evidence: str
    scope: str = "external"
    origin: str = "direct"

    def to_dict(self) -> dict:
        """Implement to dict with the module's explicit API and failure semantics."""
        return {"category": self.category, "action": self.action,
                "line": self.line, "evidence": self.evidence,
                "scope": self.scope, "origin": self.origin}


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _call_effect(name: str) -> list[tuple[str, str, str]]:
    """Return (category, action, scope) tuples for a resolved call name."""
    if not name:
        return [("io", "dynamic-call", "external")]
    leaf = name.rsplit(".", 1)[-1]
    effects: list[tuple[str, str, str]] = []
    if name in {"print", "input"} or name.startswith(("logging.", "sys.stdout", "sys.stderr")):
        effects.append(("io", name, "external"))
    if (name == "open" or name.startswith(("os.", "pathlib.", "shutil.", "tempfile."))
            and leaf in {"open", "remove", "unlink", "rename", "replace", "mkdir",
                         "makedirs", "rmdir", "removedirs", "write_text", "write_bytes",
                         "read_text", "read_bytes", "listdir", "scandir", "walk", "copy",
                         "copy2", "copytree", "move", "rmtree", "NamedTemporaryFile",
                         "TemporaryDirectory", "chmod", "chown", "truncate"}):
        effects.append(("filesystem", name, "external"))
    if name.startswith(("requests.", "urllib.", "socket.", "http.", "ftplib.",
                        "smtplib.", "aiohttp.", "httpx.", "websocket.")):
        effects.append(("network", name, "external"))
    if name.startswith(("random.", "secrets.", "uuid.")) or name in {
            "time.time", "time.monotonic", "time.perf_counter", "os.urandom"}:
        effects.append(("nondeterminism", name, "external"))
    if name.startswith(("threading.", "multiprocessing.", "asyncio.",
                        "concurrent.futures.", "subprocess.")):
        effects.append(("concurrency", name, "external"))
    if (name.startswith(("subprocess.", "asyncio.create_subprocess")) or
            name in {"os.system", "os.popen", "os.fork", "os.posix_spawn"} or
            name.startswith(("os.exec", "os.spawn"))):
        effects.append(("process", name, "external"))
        effects.append(("io", name, "external"))
    if leaf in {"append", "extend", "insert", "remove", "pop", "popitem", "clear",
                "update", "setdefault", "add", "discard", "sort", "reverse"} and "." in name:
        effects.append(("mutation", name, "receiver"))
    return effects


class _Collector(ast.NodeVisitor):
    def __init__(self) -> None:
        self.effects: list[Effect] = []
        self.external_names: set[str] = set()

    def add(self, category: str, action: str, node: ast.AST, scope: str = "external") -> None:
        """Implement add with the module's explicit API and failure semantics."""
        self.effects.append(Effect(category, action, getattr(node, "lineno", 0),
                                   ast.unparse(node)[:240], scope))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Implement visit FunctionDef with the module's explicit API and failure semantics."""
        return  # nested functions are collected in their own scope

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Implement visit AsyncFunctionDef with the module's explicit API and failure semantics."""
        return

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Implement visit ClassDef with the module's explicit API and failure semantics."""
        return

    def visit_Global(self, node: ast.Global) -> None:
        """Implement visit Global with the module's explicit API and failure semantics."""
        self.external_names.update(node.names)

    def visit_Nonlocal(self, node: ast.Nonlocal) -> None:
        """Implement visit Nonlocal with the module's explicit API and failure semantics."""
        self.external_names.update(node.names)

    def visit_Call(self, node: ast.Call) -> None:
        """Implement visit Call with the module's explicit API and failure semantics."""
        name = _name(node.func)
        for category, action, scope in _call_effect(name):
            self.add(category, action, node, scope)
        self.generic_visit(node)

    def visit_Raise(self, node: ast.Raise) -> None:
        """Implement visit Raise with the module's explicit API and failure semantics."""
        self.add("exception", "raise", node)
        self.generic_visit(node)

    def _mutation(self, target: ast.AST, node: ast.AST) -> None:
        if isinstance(target, ast.Name):
            scope = "external" if target.id in self.external_names else "local"
            self.add("mutation", f"assign:{target.id}", node, scope)
        elif isinstance(target, (ast.Attribute, ast.Subscript)):
            self.add("mutation", f"write:{_name(target) or 'item'}", node, "receiver")
        elif isinstance(target, (ast.Tuple, ast.List)):
            for item in target.elts:
                self._mutation(item, node)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Implement visit Assign with the module's explicit API and failure semantics."""
        for target in node.targets:
            self._mutation(target, node)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        """Implement visit AnnAssign with the module's explicit API and failure semantics."""
        if node.value is not None:
            self._mutation(node.target, node)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        """Implement visit AugAssign with the module's explicit API and failure semantics."""
        self._mutation(node.target, node)
        self.generic_visit(node)

    def visit_Delete(self, node: ast.Delete) -> None:
        """Implement visit Delete with the module's explicit API and failure semantics."""
        for target in node.targets:
            self._mutation(target, node)
        self.generic_visit(node)


def _function_key(name: str, effects: Iterable[Effect]) -> dict:
    rows = sorted(effects, key=lambda row: (row.line, row.category, row.action,
                                            row.evidence, row.scope))
    categories = sorted({row.category for row in rows})
    return {
        "effects": [row.to_dict() for row in rows],
        "categories": categories,
        "externally_visible": any(row.scope == "external" for row in rows),
        "pure": not any(row.scope != "local" for row in rows),
    }


def infer_effects(source: str, language: str = "python") -> dict:
    """Infer module/function effects with source lines and mutation scopes."""
    from .languages import normalize_language
    if normalize_language(language) != "python":
        raise NotImplementedError("explicit effect inference currently supports Python; "
                                  "other languages have unknown effect coverage")
    tree = ast.parse(source)
    functions: dict[str, dict] = {}
    module_nodes: list[ast.stmt] = []

    def visit_body(body: list[ast.stmt], prefix: str = "") -> None:
        """Implement visit body with the module's explicit API and failure semantics."""
        for node in body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = f"{prefix}{node.name}"
                collector = _Collector()
                for statement in node.body:
                    collector.visit(statement)
                functions[name] = {
                    **_function_key(name, collector.effects),
                    "line": node.lineno,
                    "end_line": getattr(node, "end_lineno", node.lineno),
                    "parameters": [arg.arg for arg in node.args.args],
                    "async": isinstance(node, ast.AsyncFunctionDef),
                }
                visit_body(node.body, name + ".")
            elif isinstance(node, ast.ClassDef):
                visit_body(node.body, f"{prefix}{node.name}.")
            else:
                module_nodes.append(node)

    visit_body(tree.body)
    module = _Collector()
    for node in module_nodes:
        # Do not fold nested function/class statements into module evidence.
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            module.visit(node)
    digest = hashlib.sha256(source.encode("utf-8")).hexdigest()
    return {
        "schema": SCHEMA,
        "language": "python",
        "source_sha256": digest,
        "module": _function_key("<module>", module.effects),
        "functions": functions,
        "categories": list(CATEGORIES),
        "unknowns": [],
        "coverage": {"status": "complete-for-explicit-python-effects",
                     "dynamic_dispatch": "call-site names are evidence; reflection may add unknown effects"},
    }


def transitive_effects(direct: dict[str, dict], calls: dict[str, list[str]]) -> dict[str, dict]:
    """Propagate callee effects to callers without hiding recursive cycles."""
    result = {}

    def resolve(name: str, active: frozenset[str] = frozenset()) -> tuple[list[Effect], bool]:
        """Implement resolve with the module's explicit API and failure semantics."""
        if name in result:
            return result[name]["effects"], result[name]["complete"]
        if name in active:
            return [], False
        own = [Effect(**row) for row in direct.get(name, {}).get("effects", [])]
        complete = True
        rows = list(own)
        for callee in calls.get(name, []):
            if callee not in direct:
                complete = False
                continue
            inherited, callee_complete = resolve(callee, active | {name})
            complete = complete and callee_complete
            rows.extend(Effect(row.category, row.action, row.line, row.evidence,
                               row.scope, f"inherited:{callee}") for row in inherited)
        unique = {(row.category, row.action, row.line, row.evidence,
                   row.scope, row.origin): row for row in rows}
        ordered = sorted(unique.values(), key=lambda row: (row.category, row.action,
                                                           row.line, row.origin))
        result[name] = {"effects": ordered, "complete": complete}
        return ordered, complete

    for name in direct:
        resolve(name)
    return {name: {**_function_key(name, value["effects"]),
                   "complete": value["complete"]}
            for name, value in result.items()}
