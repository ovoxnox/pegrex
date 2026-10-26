"""Static single-assignment views for Python value and dataflow analyses."""
from __future__ import annotations

import ast
import copy
from dataclasses import dataclass

SCHEMA = "pegrex.ssa.v1"


@dataclass(frozen=True)
class SSAAssignment:
    name: str
    base: str
    version: int
    value: str
    line: int
    phi: bool = False
    sources: tuple[str, ...] = ()

    def to_dict(self) -> dict:
        """Implement to dict with the module's explicit API and failure semantics."""
        return {"name": self.name, "base": self.base, "version": self.version,
                "value": self.value, "line": self.line, "phi": self.phi,
                "sources": list(self.sources)}


class _FunctionSSA:
    def __init__(self, node) -> None:
        self.node = node
        self.counter = 0
        self.environment = {}
        self.assignments: list[SSAAssignment] = []
        self.returns = []
        self.branches = []
        self.unknowns = []
        for parameter in getattr(node.args, "posonlyargs", []) + node.args.args + node.args.kwonlyargs:
            self.environment[parameter.arg] = self._new(parameter.arg, "parameter", node.lineno)
        for parameter in (node.args.vararg, node.args.kwarg):
            if parameter:
                self.environment[parameter.arg] = self._new(parameter.arg, "parameter", node.lineno)

    def _new(self, base, value, line, phi=False, sources=()) -> str:
        name = f"{base}#{self.counter}"
        self.counter += 1
        self.assignments.append(SSAAssignment(name, base, self.counter - 1,
                                              value, line, phi, tuple(sources)))
        self.environment[base] = name
        return name

    def render(self, node, environment=None) -> str:
        """Implement render with the module's explicit API and failure semantics."""
        environment = self.environment if environment is None else environment

        class Rename(ast.NodeTransformer):
            def visit_Name(self, current):
                """Implement visit Name with the module's explicit API and failure semantics."""
                if isinstance(current.ctx, ast.Load) and current.id in environment:
                    return ast.copy_location(ast.Name(id=environment[current.id], ctx=ast.Load()), current)
                return current
        return ast.unparse(Rename().visit(ast.fix_missing_locations(copy.deepcopy(node)))) if node is not None else "None"

    def block(self, statements):
        """Implement block with the module's explicit API and failure semantics."""
        for statement in statements:
            self.statement(statement)

    def statement(self, statement):
        """Implement statement with the module's explicit API and failure semantics."""
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if len(targets) != 1 or not isinstance(targets[0], ast.Name):
                self.unknowns.append(f"line {statement.lineno}: unsupported assignment target")
                return
            value = self.render(statement.value)
            self._new(targets[0].id, value, statement.lineno)
        elif isinstance(statement, ast.Return):
            self.returns.append({"line": statement.lineno, "value": self.render(statement.value)})
        elif isinstance(statement, ast.If):
            self.branch(statement)
        elif isinstance(statement, (ast.While, ast.For)):
            self.loop(statement)
        elif isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        elif isinstance(statement, (ast.Expr, ast.Pass, ast.Break, ast.Continue)):
            return
        else:
            self.unknowns.append(f"line {statement.lineno}: SSA construction does not model {type(statement).__name__}")

    def branch(self, statement):
        """Implement branch with the module's explicit API and failure semantics."""
        condition = self.render(statement.test)
        entry = dict(self.environment)
        self.block(statement.body)
        body_env = dict(self.environment)
        self.environment = dict(entry)
        self.block(statement.orelse)
        else_env = dict(self.environment)
        merged = dict(entry)
        for base in sorted(set(body_env) | set(else_env)):
            left = body_env.get(base, entry.get(base, "undefined"))
            right = else_env.get(base, entry.get(base, "undefined"))
            if left == right:
                merged[base] = left
            else:
                self.environment = merged
                merged[base] = self._new(base, f"phi({left}, {right})",
                                         statement.lineno, phi=True, sources=(left, right))
        self.environment = merged
        self.branches.append({"line": statement.lineno, "condition": condition,
                              "merge": True})

    def loop(self, statement):
        """Implement loop with the module's explicit API and failure semantics."""
        entry = dict(self.environment)
        self.block(statement.body)
        backedge = dict(self.environment)
        merged = dict(entry)
        for base in sorted(set(entry) | set(backedge)):
            left = entry.get(base, "undefined")
            right = backedge.get(base, left)
            if left != right:
                self.environment = merged
                merged[base] = self._new(base, f"loop_phi({left}, {right})",
                                         statement.lineno, phi=True, sources=(left, right))
        self.environment = merged
        self.unknowns.append(f"line {statement.lineno}: loop SSA uses one-backedge widening")


def build_function_ssa(node) -> dict:
    """Implement build function ssa with the module's explicit API and failure semantics."""
    builder = _FunctionSSA(node)
    builder.block(node.body)
    return {"name": node.name, "line": node.lineno,
            "assignments": [row.to_dict() for row in builder.assignments],
            "returns": builder.returns, "branches": builder.branches,
            "unknowns": builder.unknowns}


def build_ssa(source: str, function: str | None = None) -> dict:
    """Build immutable-by-value SSA records; unsupported constructs are explicit."""
    tree = ast.parse(source)
    functions = [node for node in ast.walk(tree)
                 if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))]
    if function is not None:
        functions = [node for node in functions if node.name == function]
        if not functions:
            raise ValueError(f"function {function!r} not found")
    reports = [build_function_ssa(node) for node in functions]
    return {"schema": SCHEMA, "functions": reports,
            "unknowns": [f"{report['name']}: {unknown}" for report in reports
                         for unknown in report["unknowns"]]}
