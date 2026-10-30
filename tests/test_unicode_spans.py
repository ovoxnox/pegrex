import pytest

from pegrex.tree_sitter_bridge import parse


@pytest.mark.parametrize("language,source,needle", [
    ("python", "# π prefix\ndef f(value):\n    return value + 1\n", "def f(value):"),
    ("go", "package p\n// π prefix\nfunc f() int { return 1 }\n", "func f()"),
    ("rust", "// π prefix\nfn f() -> i32 { 1 }\n", "fn f()"),
    ("javascript", "// π prefix\nconst value = 1;\n", "const value"),
])
def test_tree_sitter_spans_slice_python_characters(language, source, needle):
    if language != "python":
        pytest.importorskip("tree_sitter", reason="non-Python fixtures require optional parser dependencies")
    tree = parse(language, source)
    start = source.index(needle)
    found = []
    def walk(node):
        if node.pos <= start < node.endpos:
            found.append(node)
        for child in node.children:
            if hasattr(child, "tag"):
                walk(child)
    walk(tree)
    assert found
    for node in found:
        assert 0 <= node.pos <= node.endpos <= len(source)
        assert source[node.pos:node.endpos]
    assert any(source[node.pos:node.endpos].startswith(needle) for node in found)
