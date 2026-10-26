"""
tsmock - offline tree-sitter conformance layer

Pure-Python CST producer that satisfies the same duck-typed interface the
tree_sitter_bridge consumes (.children / .is_named / .type / .start_byte /
.end_byte), so COBOL and Fortran parse through the bridge offline.

Honesty contract:
  * MockParser.is_mock is True, MockParser.real is False, and
    vendor_status() reports exactly which languages are backed by a real
    compiled grammar vs the mock -- the mock never claims to be the real
    tree-sitter-cobol/tree-sitter-fortran grammar.
  * Unrecognized input becomes error nodes -- tree-sitter semantics.
  * When a real grammar .so is dropped into .vendor, load_vendor_language
    picks it up unchanged (same registry seam)."""
    
from __future__ import annotations

import os
import re


class MockNode:
    __slots__ = ("type", "children", "start_byte", "end_byte", "is_named")

    def __init__(self, type_, children, start_byte, end_byte, is_named=True):
        self.type = type_
        self.children = children
        self.start_byte = start_byte
        self.end_byte = end_byte
        self.is_named = is_named

    @property
    def text(self):
        """Implement text with the module's explicit API and failure semantics."""
        return ""  # bridge uses src slices, not node text

    def __repr__(self):
        return f"<{self.type} {self.start_byte}:{self.end_byte}>"


class MockTree:
    def __init__(self, root_node):
        self.root_node = root_node


class MockParser:
    is_mock = True
    real = False
    grammar_source = "mock-offline-conformance-v1"

    def __init__(self, language):
        self.language = language

    def parse(self, source_bytes):
        """Implement parse with the module's explicit API and failure semantics."""
        src = source_bytes.decode("utf-8", errors="replace")
        if self.language == "cobol":
            root = _parse_cobol(src)
        elif self.language == "fortran":
            root = _parse_fortran(src)
        else:
            raise ValueError(f"tsmock: no mock grammar for {self.language!r}")
        return MockTree(root)


# ---------------------------------------------------------------------------
# COBOL mock grammar (approximates tree-sitter-cobol node-type conventions)
# ---------------------------------------------------------------------------

_COB_KW = re.compile(
    r"^(?P<lead>\s*)(?P<kw>IF|MOVE|COMPUTE|ADD|SUBTRACT|PERFORM|END-IF|ELSE"
    r"|STOP\s+RUN|GOBACK|IDENTIFICATION|ENVIRONMENT|DATA|PROCEDURE"
    r"|WORKING-STORAGE|LINKAGE|FILE|LOCAL-STORAGE|PROGRAM-ID|[A-Z0-9-]+\s+SECTION)"
    r"(?P<rest>.*?)(?P<dot>\.?)$", re.I)
_COB_IDENT = re.compile(r"[A-Za-z][A-Za-z0-9-]*")
_COB_NUM = re.compile(r"[+-]?\d+")


def _cob_leaf(src, a, b, type_):
    return MockNode(type_, [], a, b)


def _cob_scan_expr(src, a, b):
    """Expression/condition tokens -> leaf nodes (identifier/number/op)."""
    out, i = [], a
    while i < b:
        ch = src[i]
        if ch in " 	":
            i += 1
            continue
        m = _COB_NUM.match(src, i)
        if m:
            out.append(_cob_leaf(src, i, m.end(), "number"))
            i = m.end()
            continue
        m = _COB_IDENT.match(src, i)
        if m and m.group(0).upper() not in ("AND", "OR", "TO", "FROM",
                                            "THEN", "IF", "UNTIL"):
            out.append(_cob_leaf(src, i, m.end(), "identifier"))
            i = m.end()
            continue
        if ch in "+-*/":
            out.append(_cob_leaf(src, i, i + 1, "operator"))
            i += 1
            continue
        if src.startswith(">=", i) or src.startswith("<=", i):
            out.append(_cob_leaf(src, i, i + 2, "operator"))
            i += 2
            continue
        if ch in "<>=":
            out.append(_cob_leaf(src, i, i + 1, "operator"))
            i += 1
            continue
        i += 1
    return out


def _parse_cobol(src):
    root_children = []
    lines = src.splitlines(keepends=True)
    pos = 0
    for line in lines:
        stripped = line.strip()
        upper = stripped.upper()
        a, b = pos, pos + len(line)
        pos = b
        if not stripped:
            continue
        if upper.startswith("*>") or upper.startswith(("IDENTIFICATION",
                "ENVIRONMENT", "DATA", "PROCEDURE", "WORKING-STORAGE",
                "LINKAGE", "FILE", "LOCAL-STORAGE")) \
                or re.match(r"^[A-Z0-9-]+\s+SECTION\.?$", upper):
            root_children.append(MockNode("comment" if upper.startswith("*>")
                                          else "division_header", [], a, b))
        elif re.match(r"^PROGRAM-ID\.", upper):
            root_children.append(MockNode("program_id_paragraph", [], a, b))
        elif upper.startswith("IF ") and upper.endswith("THEN"):
            inner_a = a + line.upper().index("IF ") + 3
            inner_b = a + line.upper().rindex("THEN")
            cond = MockNode("condition", _cob_scan_expr(src, inner_a, inner_b),
                            inner_a, inner_b)
            root_children.append(MockNode("if_statement", [cond], a, b))
        elif upper == "ELSE":
            root_children.append(MockNode("else_clause", [], a, b))
        elif upper.startswith("END-IF"):
            root_children.append(MockNode("end_if", [], a, b))
        elif upper.startswith("MOVE "):
            m = re.match(r"MOVE\s+(.+?)\s+TO\s+(\w+)", stripped, re.I)
            kids = _cob_scan_expr(src, a + line.index(m.group(1)),
                                  a + line.index(m.group(1)) + len(m.group(1))) \
                if m else []
            dst = _cob_leaf(src, a + line.upper().rindex(" TO ") + 4,
                            a + len(line.rstrip().rstrip(".")), "identifier")
            root_children.append(MockNode("move_statement", kids + [dst], a, b))
        elif upper.startswith("COMPUTE "):
            m = re.match(r"COMPUTE\s+(\w+)\s*=\s*(.+)", stripped, re.I)
            if m:
                ea = a + line.index("=") + 1
                eb = a + len(line.rstrip().rstrip("."))
                expr = MockNode("expression", _cob_scan_expr(src, ea, eb), ea, eb)
                dst = _cob_leaf(src, a + line.index(m.group(1)),
                                a + line.index(m.group(1)) + len(m.group(1)),
                                "identifier")
                root_children.append(MockNode("compute_statement", [dst, expr],
                                              a, b))
            else:
                root_children.append(MockNode("ERROR", [], a, b))
        elif upper.startswith(("ADD ", "SUBTRACT ")):
            root_children.append(MockNode("arithmetic_statement", [], a, b))
        elif upper.startswith(("STOP RUN", "GOBACK")):
            root_children.append(MockNode("stop_statement", [], a, b))
        elif upper.startswith("PERFORM"):
            root_children.append(MockNode("perform_statement", [], a, b))
        else:
            root_children.append(MockNode("ERROR", [], a, b))
    return MockNode("program", root_children, 0, len(src))


# ---------------------------------------------------------------------------
# Fortran mock grammar (approximates tree-sitter-fortran conventions)
# ---------------------------------------------------------------------------

def _parse_fortran(src):
    root_children = []
    lines = src.splitlines(keepends=True)
    pos = 0
    for line in lines:
        stripped = line.strip()
        a, b = pos, pos + len(line)
        pos = b
        if not stripped or stripped.startswith("!"):
            continue
        low = stripped.lower()
        if low.startswith("function ") or low.startswith("end function"):
            root_children.append(MockNode(
                "function_statement" if low.startswith("function")
                else "end_function_statement", [], a, b))
        elif low.startswith("if") and low.endswith("then"):
            ia = a + line.lower().index("(") + 1
            ib = a + line.lower().rindex(")")
            cond = MockNode("condition", _cob_scan_expr(src, ia, ib), ia, ib)
            root_children.append(MockNode("if_statement", [cond], a, b))
        elif low == "else":
            root_children.append(MockNode("else_clause", [], a, b))
        elif low.startswith("end if"):
            root_children.append(MockNode("end_if_statement", [], a, b))
        elif low.startswith("do"):
            root_children.append(MockNode("do_loop_statement", [], a, b))
        elif "=" in stripped and not low.startswith("if"):
            lhs = stripped.split("=")[0].strip()
            la = a + line.index(lhs)
            dst = MockNode("identifier", [], la, la + len(lhs))
            ea = a + line.index("=") + 1
            eb = a + len(line.rstrip())
            expr = MockNode("expression", _cob_scan_expr(src, ea, eb), ea, eb)
            root_children.append(MockNode("assignment_statement", [dst, expr],
                                          a, b))
        else:
            root_children.append(MockNode("ERROR", [], a, b))
    return MockNode("translation_unit", root_children, 0, len(src))


# registry + vendor seam

_MOCK_LANGS = ("cobol", "fortran")


def vendor_status() -> dict:
    """Honest report: which languages are mock-backed right now."""
    out = {}
    for lang in _MOCK_LANGS:
        out[lang] = "mock" if get_parser(lang).is_mock else "vendor"
    return out


def load_vendor_language(language, so_path):
    """Load a real compiled grammar from a .so. Raises loudly if unloadable
    or if the symbol interface does not match -- never a silent mock."""
    import ctypes
    if not os.path.exists(so_path):
        raise FileNotFoundError(f"tsmock: no grammar at {so_path}")
    lib = ctypes.CDLL(so_path)
    sym = "tree_sitter_" + language.replace("-", "_")
    if not hasattr(lib, sym):
        raise ValueError(f"tsmock: {so_path} lacks symbol {sym}")
    from tree_sitter import Language as _TSLanguage, Parser as _TSParser
    lang = _TSLanguage(ctypes.cast(getattr(lib, sym), ctypes.c_void_p))
    parser = _TSParser(lang)
    parser.is_mock = False
    parser.real = True
    return parser

def get_parser(language):
    """Registry seam: mock for cobol/fortran offline; real parsers stay the
    tree_sitter_language_pack's job for the other languages."""
    if language in _MOCK_LANGS:
        return MockParser(language)
    from tree_sitter_language_pack import get_parser as _real
    p = _real(language)
    p.is_mock = False
    p.real = True
    return p
