"""Dependency-free Python AST adapter implementing PegRex's Node contract.

Used when optional Tree-sitter bindings are absent. The adapter covers module,
function, call, branch, return and common statement nodes, and translates the
Python AST's UTF-8 byte columns to the character-offset convention used by
PegRex. It is an AST adapter, not a replacement for the full Python grammar.
"""
from __future__ import annotations
import ast
from .peg import Node


def _line_starts(source: str) -> list[int]:
    starts = [0]
    total = 0
    for line in source.splitlines(keepends=True):
        total += len(line)
        starts.append(total)
    return starts


def _span(source: str, node: ast.AST, starts: list[int]) -> tuple[int, int]:
    def offset(line_number: int, byte_column: int) -> int:
        """Implement offset with the module's explicit API and failure semantics."""
        idx = max(0, min(line_number - 1, max(0, len(starts) - 2)))
        line_start = starts[idx]
        line_end = starts[idx + 1] if idx + 1 < len(starts) else len(source)
        line = source[line_start:line_end]
        prefix = line.encode("utf-8")[:byte_column].decode("utf-8", errors="ignore")
        return line_start + len(prefix)
    sl = getattr(node, "lineno", 1) or 1
    sc = getattr(node, "col_offset", 0) or 0
    el = getattr(node, "end_lineno", sl) or sl
    ec = getattr(node, "end_col_offset", sc) or sc
    return offset(sl, sc), offset(el, ec)


def _convert(source: str, node: ast.AST, starts: list[int]) -> Node:
    start, end = _span(source, node, starts) if hasattr(node, "lineno") else (0, len(source))
    get = lambda n: _convert(source, n, starts)
    text = ast.get_source_segment(source, node) or ast.dump(node, include_attributes=False)

    if isinstance(node, ast.Module):
        return Node("module", 0, len(source), [get(item) for item in node.body])
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        ns, ne = _span(source, node.args, starts)
        identifier = Node("identifier", start, min(end, start + len(node.name)), [node.name])
        body_nodes = [get(item) for item in node.body]
        body = Node("block", body_nodes[0].pos if body_nodes else end,
                    body_nodes[-1].endpos if body_nodes else end, body_nodes)
        return Node("function_definition", start, end, [identifier, body])
    if isinstance(node, ast.ClassDef):
        identifier = Node("identifier", start, min(end, start + len(node.name)), [node.name])
        return Node("class_definition", start, end, [identifier] + [get(x) for x in node.body])
    if isinstance(node, ast.If):
        cs, ce = _span(source, node.test, starts)
        condition = Node("condition", cs, ce, [ast.unparse(node.test)])
        children = [condition, Node("block", start, end, [get(x) for x in node.body])]
        if node.orelse:
            other = [get(x) for x in node.orelse]
            children.append(Node("else_clause", other[0].pos, other[-1].endpos,
                                 [Node("block", other[0].pos, other[-1].endpos, other)]))
        return Node("if_statement", start, end, children)
    if isinstance(node, (ast.While, ast.For, ast.AsyncFor)):
        test = node.test if isinstance(node, ast.While) else node.iter
        cs, ce = _span(source, test, starts)
        condition_text = ast.unparse(test) if isinstance(node, ast.While) else f"iterates({ast.unparse(test)})"
        condition = Node("condition", cs, ce, [condition_text])
        return Node("while_statement" if isinstance(node, ast.While) else "for_statement",
                    start, end, [condition, Node("block", start, end, [get(x) for x in node.body])])
    if isinstance(node, ast.Return):
        expr = ast.get_source_segment(source, node.value) if node.value is not None else ""
        children = [get(node.value)] if node.value is not None else [""]
        return Node("return_statement", start, end, children)
    if isinstance(node, ast.Call):
        children = [get(node.func)] + [get(arg) for arg in node.args]
        children += [get(kw.value) for kw in node.keywords]
        return Node("call_expression", start, end, children)
    if isinstance(node, ast.Name):
        return Node("identifier", start, end, [node.id])
    if isinstance(node, ast.Constant):
        return Node("string" if isinstance(node.value, str) else "literal", start, end, [text])
    if isinstance(node, ast.Expr):
        return Node("expression_statement", start, end, [get(node.value)])
    if isinstance(node, ast.Assign):
        return Node("assignment", start, end, [get(t) for t in node.targets] + [get(node.value)])
    if isinstance(node, ast.AnnAssign):
        children = [get(node.target)]
        if node.value is not None:
            children.append(get(node.value))
        return Node("assignment", start, end, children)
    if isinstance(node, ast.Raise):
        children = [get(node.exc)] if node.exc is not None else []
        return Node("raise_statement", start, end, children or [text])
    if isinstance(node, ast.Break):
        return Node("break_statement", start, end, [text])
    if isinstance(node, ast.Continue):
        return Node("continue_statement", start, end, [text])
    children = [get(child) for child in ast.iter_child_nodes(node)
                if hasattr(child, "lineno")]
    return Node(type(node).__name__.lower(), start, end, children or [text])


def parse_module(source: str) -> Node:
    """Implement parse module with the module's explicit API and failure semantics."""
    tree = ast.parse(source)
    return _convert(source, tree, _line_starts(source))


def parse_function_body(source: str, name: str | None = None) -> Node:
    """Implement parse function body with the module's explicit API and failure semantics."""
    root = parse_module(source)
    for child in root.children:
        if isinstance(child, Node) and child.tag == "function_definition":
            identifier = next((n for n in child.children if isinstance(n, Node) and n.tag == "identifier"), None)
            if name is None or (identifier and identifier.children and identifier.children[0] == name):
                body = next((n for n in child.children if isinstance(n, Node) and n.tag == "block"), None)
                if body is not None:
                    return body
    raise ValueError(f"no top-level function {name!r} found" if name else "no top-level function found")
