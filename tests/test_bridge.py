"""tree-sitter bridge tested with a duck-typed mock CST (bindings are an
optional dependency; the normalizer only needs the documented shape)."""


class FakeTSNode:
    def __init__(self, type_, children=(), named=True, start=0, end=0):
        self.type = type_
        self.children = list(children)
        self.is_named = named
        self.child_count = len(self.children)
        self.start_byte = start
        self.end_byte = end


def test_ts_to_pegrex_normalization():
    from pegrex.tree_sitter_bridge import ts_to_pegrex
    cst = FakeTSNode("function_definition", [
        FakeTSNode("identifier", start=4, end=7),      # name
        FakeTSNode("(", named=False, start=7, end=8),  # punct: skipped
        FakeTSNode("block", [
            FakeTSNode("return_statement", [
                FakeTSNode("number", start=20, end=21),
            ], start=10, end=22),
        ], start=9, end=23),
    ], start=0, end=24)
    node = ts_to_pegrex(cst)
    assert node.tag == "function_definition"
    tags = [c.tag for c in node.children]
    assert "identifier" in tags and "(" not in tags
    block = next(c for c in node.children if c.tag == "block")
    assert block.children[0].tag == "return_statement"
    assert node.pos == 0 and node.endpos == 24


def test_language_map_covers_frontends():
    from pegrex.tree_sitter_bridge import LANGUAGE_MAP
    assert {"python", "go", "rust", "lua", "c"} <= set(LANGUAGE_MAP)
