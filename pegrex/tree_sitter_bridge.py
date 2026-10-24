"""
tree_sitter_bridge

║  Tree-sitter CST -> pegrex Node normalization. Dependency: 
║  pip install tree-sitter tree-sitter-language-pack
║  TAGSPECS maps Python/Go/Rust control tags."""

from __future__ import annotations

from .cfg import TagSpec
from .peg import Node as PNode


def ts_to_pegrex(ts_node, src: str = "") -> PNode:
    """Recursively convert a tree-sitter node (duck-typed; no hard import).

    Named children only (anonymous punctuation filtered); leaf nodes keep
    their source text so text-based renderers work."""
    children = [ts_to_pegrex(ch, src) for ch in ts_node.children if ch.is_named]
    if not children and src:
        children = [src[ts_node.start_byte:ts_node.end_byte]]
    return PNode(ts_node.type, ts_node.start_byte, ts_node.end_byte, children)


def parse(language: str, source: str) -> PNode:
    """CST -> pegrex Node. cobol/fortran resolve through the offline mock
    registry when no real grammar is vendored (tsmock.is_mock marks it)."""
    if language in ("cobol", "fortran"):
        from . import tsmock
        tree = tsmock.get_parser(language).parse(source.encode())
        return ts_to_pegrex(tree.root_node, source)
    vendored = {"python": ("tree_sitter_python", "language"),
                "go": ("tree_sitter_go", "language"),
                "rust": ("tree_sitter_rust", "language"),
                "javascript": ("tree_sitter_javascript", "language"),
                "typescript": ("tree_sitter_typescript", "language_typescript"),
                "tsx": ("tree_sitter_typescript", "language_tsx"),
                "julia": ("tree_sitter_julia", "language"),
                "kotlin": ("tree_sitter_kotlin", "language"),
                "zig": ("tree_sitter_zig", "language"),
                "solidity": ("tree_sitter_solidity", "language")}
    hit = vendored.get(language)
    if hit is not None:
        modname, attr = hit
        mod = __import__(modname)
        from tree_sitter import Language, Parser
        tree = Parser(Language(getattr(mod, attr)())).parse(source.encode())
        return ts_to_pegrex(tree.root_node, source)
    try:
        from tree_sitter_language_pack import get_parser
    except ImportError as e:
        raise ImportError(
            "tree-sitter bridge requires: pip install tree-sitter "
            "tree-sitter-language-pack (or use the vendored bindings)") from e
    tree = get_parser(language).parse(source.encode())
    return ts_to_pegrex(tree.root_node, source)


LANGUAGE_MAP = {"python": "python", "go": "go", "rust": "rust",
                "lua": "lua", "c": "c"}


# ── pipeline bindings
def _cond_then_else(ch):
    """python/go if_statement, rust if_expression: [cond, then, else?]."""
    return ch[0], ch[1], ch[2] if len(ch) > 2 else None


def _while_parts(ch):
    return ch[0], ch[1]


def _py_for(ch):
    """python for_statement named children: [left, right, body]."""
    return ch[1], ch[2]


def _py_try(node):
    """try_statement parts: (body, handlers) for cfg._try."""
    kids = [c for c in node.children if hasattr(c, "tag")]
    return kids


def _py_if(ch):
    """python if_statement: [condition, consequence, else_clause?]."""
    els = ch[2] if len(ch) > 2 else None
    if els is not None and getattr(els, "tag", None) == "else_clause":
        inner = [c for c in els.children if hasattr(c, "tag")]
        els = inner[-1] if inner else els
    return ch[0], ch[1], els


def _go_while(ch):
    """go for_statement: [condition, body] or [for_clause, body].
    for_clause named children: [init, condition, post]."""
    first, body = ch[0], ch[-1]
    if getattr(first, "tag", None) == "for_clause":
        parts = [c for c in first.children if hasattr(c, "tag")]
        cond = parts[1] if len(parts) >= 2 else parts[0]
        return cond, body
    return first, body


def _mk(tag: str, fn):
    """Per-language parts-extractor carrying its dispatch tag."""
    g = lambda ch: fn(ch)
    g._tag = tag
    return g


TAGSPECS: dict[str, TagSpec] = {
    "javascript": TagSpec(block="statement_block",
                          if_=_mk("if_statement", _cond_then_else),
                          while_=_mk("while_statement", _while_parts),
                          for_=_mk("for_statement", _while_parts),
                          return_="return_statement",
                          break_="break_statement",
                          continue_="continue_statement",
                      match_=_mk("match_statement", _while_parts),
                      with_=_mk("with_statement", _while_parts)),
    "solidity": TagSpec(block="block",
                          if_=_mk("if_statement", _cond_then_else),
                          while_=_mk("while_statement", _while_parts),
                          for_=_mk("for_statement", _while_parts),
                          return_="return_statement",
                          break_="break_statement"),
    "julia": TagSpec(block="block",
                     if_=_mk("if_statement", _cond_then_else),
                     while_=_mk("while_statement", _while_parts),
                     for_=_mk("for_statement", _while_parts),
                     return_="return_statement",
                     break_="break_statement"),
    "kotlin": TagSpec(block="block",
                      if_=_mk("if_expression", _cond_then_else),
                      while_=_mk("while_statement", _while_parts),
                      for_=_mk("for_statement", _while_parts),
                      return_="return_expression",
                      break_="break_statement"),
    "zig": TagSpec(block="block",
                   if_=_mk("if_statement", _cond_then_else),
                   while_=_mk("while_statement", _while_parts),
                   for_=_mk("for_statement", _while_parts),
                   return_="return_expression",
                   break_="break_expression"),
    "python": TagSpec(block="block",
                      if_=_mk("if_statement", _py_if),
                      while_=_mk("while_statement", _while_parts),
                      for_=_mk("for_statement", _py_for),
                      try_=_mk("try_statement", _py_try),
                      return_="return_statement", break_="break_statement",
                      continue_="continue_statement",
                      match_=_mk("match_statement", _while_parts),
                      with_=_mk("with_statement", _while_parts)),
    "go": TagSpec(block="block",
                  if_=_mk("if_statement", _cond_then_else),
                  while_=_mk("for_statement", _go_while),
                  return_="return_statement", break_="break_statement"),
    "rust": TagSpec(block="block",
                    if_=_mk("if_expression", _cond_then_else),
                    while_=_mk("while_expression", _while_parts),
                    return_="return_expression", break_="break_expression",
                    match_=_mk("match_expression", _while_parts),
                    tail_return=("unary_expression", "binary_expression",
                                 "integer_literal", "identifier",
                                 "call_expression", "if_expression",
                                 "match_expression", "block")),
}
