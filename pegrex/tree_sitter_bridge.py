"""Registry-backed parser bridge and source-coordinate normalization.

Tree-sitter spans are UTF-8 byte offsets. PegRex Node spans are Python
character offsets so every consumer can safely slice the original ``str``.
The conversion map is built once per source, not once per node.
"""
from __future__ import annotations

from array import array

from .limits import MAX_AST_NODES, MAX_SOURCE_BYTES
from .cfg import TagSpec
from .peg import Node as PNode


def _byte_to_char_offsets(source: str) -> array:
    """Map UTF-8 byte offsets to Python character offsets compactly.

    A 32-bit array keeps the map to roughly four bytes per UTF-8 byte instead
    of a Python integer object per byte. PegRex's source-size limit keeps the
    character offsets within the unsigned 32-bit range.
    """
    raw_size = len(source.encode("utf-8"))
    offsets = array("I", [0]) * (raw_size + 1)
    byte_offset = 0
    char_offset = 0
    for char in source:
        width = len(char.encode("utf-8"))
        for index in range(width):
            offsets[byte_offset + index] = char_offset
        byte_offset += width
        char_offset += 1
        offsets[byte_offset] = char_offset
    return offsets


def _normalize_node(ts_node, source: str, offsets) -> PNode:
    """Normalize a parser subtree iteratively, with an explicit node budget."""
    built: dict[int, PNode] = {}
    stack = [(ts_node, False)]
    visited = 0
    while stack:
        current, ready = stack.pop()
        named_children = [child for child in current.children if child.is_named]
        if not ready:
            visited += 1
            if visited > MAX_AST_NODES:
                raise ValueError(f"parse tree exceeds {MAX_AST_NODES} named-node budget")
            stack.append((current, True))
            stack.extend((child, False) for child in reversed(named_children))
            continue
        if offsets is None:
            start, end = current.start_byte, current.end_byte
        else:
            start = offsets[min(current.start_byte, len(offsets) - 1)]
            end = offsets[min(current.end_byte, len(offsets) - 1)]
        children = [built[id(child)] for child in named_children]
        if not children and source:
            children = [source[start:end]]
        built[id(current)] = PNode(current.type, start, end, children)
    return built[id(ts_node)]


def normalize_tree(ts_node, source: str = "") -> PNode:
    """Normalize a Tree-sitter tree into Python character-offset coordinates.

    For synthetic test nodes without source text, preserve their given offsets.
    Traversal is iterative to avoid Python recursion exhaustion on deeply nested
    input; an explicit named-node budget bounds allocation.
    """
    if source and len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError(f"source input exceeds {MAX_SOURCE_BYTES} UTF-8 bytes")
    offsets = _byte_to_char_offsets(source) if source else None
    return _normalize_node(ts_node, source, offsets)


def ts_to_pegrex(ts_node, src: str = "") -> PNode:
    """Backwards-compatible name for :func:`normalize_tree`."""
    return normalize_tree(ts_node, src)


def parse_tree_sitter(language: str, source: str) -> PNode:
    if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise ValueError(f"source input exceeds {MAX_SOURCE_BYTES} UTF-8 bytes")
    """Low-level registered Tree-sitter parse; use ``languages.parse_source`` publicly."""
    from .languages import get_language, load_tree_sitter_parser
    spec = get_language(language)
    if "parse" not in spec.capabilities:
        raise NotImplementedError(f"parsing is not registered for {spec.name}")
    if spec.parse_adapter != "tree-sitter":
        raise NotImplementedError(
            f"{spec.name} uses parse adapter {spec.parse_adapter!r}, not Tree-sitter")
    try:
        parser = load_tree_sitter_parser(spec.name)
    except ImportError:
        if spec.parser == "tree-sitter-or-stdlib":
            from .python_ast import parse_module
            return parse_module(source)
        raise
    tree = parser.parse(source.encode("utf-8"))
    # Native mocks already expose byte spans and follow the same bridge contract.
    return normalize_tree(tree.root_node, source)


def parse(language: str, source: str) -> PNode:
    """Compatibility adapter routed through the central language registry."""
    from .languages import parse_source
    return parse_source(language, source)


# Historical public view derived from the central registry. Values are canonical
# language names; this is metadata, not an independent parser dispatch table.
from .languages import LANGUAGES as _LANGUAGES
LANGUAGE_MAP = {name: name for name, spec in _LANGUAGES.items()
                if "parse" in spec.capabilities}


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
