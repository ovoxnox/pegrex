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
from pegrex.fortranfront import FortranError

FTN = chr(10).join(["function absval(n)", "  if (n >= 0) then",
                    "    absval = n", "  else", "    absval = -n",
                    "  end if", "end function"])


def _w(src):
    p = os.path.join(tempfile.mkdtemp(), "a.f90")
    open(p, "w").write(src)
    return p


def test_extension_dispatch():
    cs = api.contracts(_w(FTN))
    assert len(cs) == 2


def test_relational_operators_three_paths():
    src = chr(10).join(["function classify(n)", "  if (n .GT. 0) then",
                        "    classify = 1", "  else", "    if (n .EQ. 0) then",
                        "      classify = 0", "    else", "      classify = -1",
                        "    end if", "  end if", "end function"])
    from pegrex.fortranfront import contracts
    assert len(contracts(src)) == 3


def test_do_loop_refused():
    from pegrex.fortranfront import contracts
    with pytest.raises(FortranError):
        contracts(FTN.replace("  if (n >= 0) then", "  do i = 1, n"))


def test_one_line_if_refused():
    from pegrex.fortranfront import contracts
    with pytest.raises(FortranError):
        contracts(chr(10).join(["function f(n)", "  if (n .GT. 0) f = 1",
                                "  f = 0", "end function"]))


def test_cross_language_equivalence():
    COB = chr(10).join(["       *> pegrex: result RES",
                        "       PROCEDURE DIVISION.",
                        "           IF N >= 0 THEN",
                        "               MOVE N TO RES",
                        "           ELSE",
                        "               COMPUTE RES = 0 - N",
                        "           END-IF.", "           GOBACK."])
    from pegrex.semantics import verify_patch
    d = tempfile.mkdtemp()
    pc = os.path.join(d, "a.cob"); open(pc, "w").write(COB)
    pf = os.path.join(d, "a.f90"); open(pf, "w").write(FTN)
    assert verify_patch(pc, pf)["verified"] is True
