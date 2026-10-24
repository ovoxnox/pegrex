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
from pegrex.emitter import emit_python
from pegrex.semantics import verify_patch

SRC = chr(10).join(["def absval(n):", "    if n >= 0:", "        return n",
                    "    return -n", ""])


def _w(src, name="m.py"):
    p = os.path.join(tempfile.mkdtemp(), name)
    open(p, "w").write(src)
    return p


def test_emission_verified_against_original():
    orig = _w(SRC)
    code = emit_python("absval", ["n"], api.contracts(orig))
    assert verify_patch(orig, _w(code, "e.py"))["verified"] is True


def test_emitted_code_executes():
    orig = _w(SRC)
    code = emit_python("absval", ["n"], api.contracts(orig))
    ns = {}
    exec(code, ns)
    assert ns["absval"](5) == 5 and ns["absval"](-7) == 7


def test_exhaustiveness_refusal():
    partial = [(frozenset(["(n >= 0)"]), "n")]   # single guard, no cover
    with pytest.raises(ValueError):
        emit_python("f", ["n"], partial)


def test_tampered_refused():
    orig = _w(SRC)
    code = emit_python("absval", ["n"], api.contracts(orig))
    tampered = code.replace("return (-n)", "return n", 1)
    out = verify_patch(orig, _w(tampered, "t.py"))
    assert out["verified"] is False and out["counterexample"]
