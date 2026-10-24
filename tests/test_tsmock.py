try:
    import pytest
except ImportError:
    class _Raises:
        def __init__(self, exc): self.exc = exc
        def __enter__(self): return self
        def __exit__(self, t, v, tb):
            assert t is not None and issubclass(t, self.exc), f"expected {self.exc}"
            return True
    class _PytestShim:
        @staticmethod
        def raises(exc): return _Raises(exc)
    pytest = _PytestShim()


from pegrex import tree_sitter_bridge as tb
from pegrex import tsmock

COB = chr(10).join(["       IDENTIFICATION DIVISION.",
                    "       PROGRAM-ID. ABSVAL.",
                    "       PROCEDURE DIVISION.",
                    "           IF N >= 0 THEN",
                    "               MOVE N TO RES", "           END-IF.",
                    "           GOBACK."])
FTN = chr(10).join(["function absval(n)", "  if (n >= 0) then",
                    "    absval = n", "  end if", "end function"])


def test_bridge_parse_both_languages():
    assert tb.parse("cobol", COB).tag == "program"
    assert tb.parse("fortran", FTN).tag == "translation_unit"


def test_determinism():
    def shape(n):
        return (n.tag, n.pos, n.endpos,
                tuple(shape(c) for c in n.children if not isinstance(c, str)))
    assert shape(tb.parse("cobol", COB)) == shape(tb.parse("cobol", COB))


def test_garbage_is_error_node():
    t = tb.parse("cobol", "       TOTAL GARBAGE LINE HERE.")
    assert "ERROR" in [c.tag for c in t.children if not isinstance(c, str)]


def test_mock_honesty():
    assert tsmock.get_parser("cobol").is_mock is True
    assert tsmock.get_parser("cobol").real is False
    assert tsmock.vendor_status() == {"cobol": "mock", "fortran": "mock"}


def test_vendor_seam_refuses_missing():
    with pytest.raises(FileNotFoundError):
        tsmock.load_vendor_language("cobol", "/nonexistent/g.so")
