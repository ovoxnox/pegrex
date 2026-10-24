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

from pegrex.refine import discharge_source, parse_contracts

SRC = chr(10).join(["# requires: n != 0", "# ensures: result >= 0",
                    "def absval(n):", "    if n >= 0:", "        return n",
                    "    return -n", ""])


def _w(src):
    p = os.path.join(tempfile.mkdtemp(), "r.py")
    open(p, "w").write(src)
    return p


def test_parse_contracts():
    c = parse_contracts(SRC)
    assert c == {"requires": ["n != 0"], "ensures": ["result >= 0"]}


def test_ensures_discharged_both_paths():
    v = discharge_source(_w(SRC), parse_contracts(SRC))
    assert all(e["status"] == "discharged" for x in v for e in x["ensures"])


def test_requires_per_path_honesty():
    v = discharge_source(_w(SRC), parse_contracts(SRC))
    statuses = sorted(r["status"] for x in v for r in x["requires"])
    assert statuses == ["respected", "violated"]


def test_false_ensures_never_discharged():
    bad = SRC.replace("result >= 0", "result > 5")
    v = discharge_source(_w(bad), parse_contracts(bad))
    assert all(e["status"] != "discharged" for x in v for e in x["ensures"])


def test_nonlinear_undischarged_not_guessed():
    nl = SRC.replace("    return -n", "    return n * n")
    v = discharge_source(_w(nl), parse_contracts(nl))
    assert any(e["status"] == "undischarged" for x in v for e in x["ensures"])
