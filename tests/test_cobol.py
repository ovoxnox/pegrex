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


import os
import tempfile

from pegrex import api
from pegrex.cobolfront import CobolError

COB = chr(10).join([
    "       IDENTIFICATION DIVISION.",
    "       PROGRAM-ID. ABSVAL.",
    "       *> pegrex: result RES",
    "       PROCEDURE DIVISION.",
    "           IF N >= 0 THEN",
    "               MOVE N TO RES",
    "           ELSE",
    "               COMPUTE RES = 0 - N",
    "           END-IF.",
    "           GOBACK.",
])


def _w(src):
    p = os.path.join(tempfile.mkdtemp(), "a.cob")
    open(p, "w").write(src)
    return p


def test_extension_dispatch():
    cs = api.contracts(_w(COB))
    assert len(cs) == 2


def test_symbolic_arithmetic():
    src = (COB.replace("MOVE N TO RES",
                       "COMPUTE RES = N" + chr(10) + "           ADD 1 TO RES")
              .replace("COMPUTE RES = 0 - N",
                       "COMPUTE RES = 0" + chr(10) +
                       "           SUBTRACT N FROM RES"))
    from pegrex.cobolfront import contracts
    cs = contracts(src)
    assert str(cs[0][1]) == "(N + 1)", cs
    assert str(cs[1][1]) == "(0 - N)", cs


def test_perform_refused():
    from pegrex.cobolfront import contracts
    with pytest.raises(CobolError):
        contracts(COB.replace("IF N >= 0 THEN", "PERFORM UNTIL N <= 0"))


def test_missing_endif_refused():
    from pegrex.cobolfront import contracts
    with pytest.raises(CobolError):
        contracts(COB.replace("           END-IF.", "       *> gone"))


def test_missing_result_refused():
    from pegrex.cobolfront import contracts
    with pytest.raises(CobolError):
        contracts(COB.replace("*> pegrex: result RES", "*> none"))
