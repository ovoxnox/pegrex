"""Conservative termination, allocation-site, and asymptotic bounds."""
from __future__ import annotations
import ast
SCHEMA = "pegrex.resource-bounds.v1"


def _range(node):
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "range" and len(node.args) == 1:
        if isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, int):
            return max(0, node.args[0].value), str(node.args[0].value)
        if isinstance(node.args[0], ast.Name): return None, node.args[0].id
    return None, None


def _block(statements, function, depth=0):
    allocations, exponent, unknowns = 0, 0, []
    termination = True
    allocation_expression = "0"
    def add_alloc(expr):
        """Implement add alloc with the module's explicit API and failure semantics."""
        nonlocal allocation_expression
        allocation_expression = allocation_expression + "+" + expr
    for statement in statements:
        for node in ast.walk(statement):
            if isinstance(node, (ast.List, ast.Dict, ast.Set, ast.ListComp, ast.SetComp, ast.DictComp)):
                allocations += 1; add_alloc("1")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == function:
                termination = False; unknowns.append("recursion outside termination fragment")
        if isinstance(statement, (ast.For, ast.While)):
            body_alloc, body_exp, body_term, body_unknown, body_expr = _block(statement.body, function, depth + 1)
            unknowns.extend(body_unknown); termination = termination and body_term
            if isinstance(statement, ast.For):
                count, label = _range(statement.iter)
                if label is None:
                    termination = False; exponent = None; unknowns.append("non-range loop bound unknown")
                else:
                    exponent = None if body_exp is None else body_exp + 1
                    if count is not None:
                        allocations += count * body_alloc; add_alloc(f"{count}*({body_expr})")
                    elif body_alloc:
                        allocations = None; add_alloc(f"{label}*({body_expr})")
            else:
                variant = False
                if isinstance(statement.test, ast.Compare) and len(statement.test.ops) == 1                         and isinstance(statement.test.left, ast.Name)                         and isinstance(statement.test.ops[0], (ast.Gt, ast.GtE)):
                    name = statement.test.left.id
                    variant = any(isinstance(row, ast.AugAssign) and isinstance(row.target, ast.Name)
                                  and row.target.id == name and isinstance(row.op, ast.Sub)
                                  and isinstance(row.value, ast.Constant) and row.value.value > 0
                                  for row in statement.body)
                if variant:
                    exponent = None if body_exp is None else body_exp + 1
                    if body_alloc: allocations = None; add_alloc(f"iterations*({body_expr})")
                else:
                    termination = False; exponent = None
                    if body_alloc: allocations = None
                    unknowns.append("while loop has no proved decreasing variant")
        elif isinstance(statement, ast.Break):
            unknowns.append("break outside structured resource fragment")
    return allocations, exponent, termination, unknowns, allocation_expression


def analyze_resource_bounds(source, *, function=None) -> dict:
    """Allocation means allocation sites, not byte-exact memory consumption."""
    try: tree = ast.parse(source)
    except SyntaxError as error:
        return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown", "functions": [],
                "unknowns": [f"parse error: {error}"]}
    rows = []
    for node in tree.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or (function and node.name != function): continue
        if isinstance(node, ast.AsyncFunctionDef):
            rows.append({"function": node.name, "verdict": "unknown", "unknowns": ["async resource fragment unsupported"]}); continue
        allocations, exponent, termination, unknowns, expression = _block(node.body, node.name)
        verdict = "proved" if termination and exponent is not None and allocations is not None and not unknowns else "unknown"
        rows.append({"function": node.name, "verdict": verdict,
                     "termination": "proved" if termination else "unknown",
                     "allocation_sites": allocations, "allocation_expression": expression,
                     "worst_case_complexity": "O(1)" if exponent == 0 else f"O(n^{exponent})" if exponent and exponent > 1 else "O(n)" if exponent == 1 else None,
                     "fragment": "structured range loops and simple decreasing integer while variants",
                     "unknowns": sorted(set(unknowns))})
    unknowns = [f"{row['function']}: resource bound incomplete" for row in rows if row["verdict"] == "unknown"]
    return {"schema": SCHEMA, "schema_version": 1,
            "verdict": "unknown" if unknowns or not rows else "proved",
            "functions": rows, "unknowns": unknowns}
