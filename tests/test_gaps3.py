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


"""Unit tests for the m148/m149/m163/m164 gap modules."""
import os
import tempfile

from pegrex import ic3, insure
from pegrex.linsolve import atoms_of
from pegrex.ir import lower_condition


def test_rank_synth_families():
    from pegrex.rank import find_ranking, synthesize_ranking
    assert find_ranking("i <= n", {"i": 1}) == "n - i + 1"
    lex = synthesize_ranking("i <= n and j <= m", {"i": 1, "j": 1},
                             templates=("lex",))
    assert lex["discharged"] is True, lex
    nop = synthesize_ranking("i < n", {"i": 0}, templates=("unit",))
    assert nop["discharged"] is False


def test_ic3_prove_refute_unknown():
    INIT = atoms_of(lower_condition("i >= 1 and i <= 1 and n >= 1"))
    out = ic3.prove(INIT, ["i_p - i = 1"], "i >= 1", max_frames=4)
    assert out["status"] == "proved", out
    bad = atoms_of(lower_condition("i >= -5 and i <= -5 and n >= 1"))
    out2 = ic3.prove(bad, ["i_p - i = 1"], "i >= 1")
    assert out2["status"] == "refuted" and out2["witness"], out2
    out3 = ic3.prove(["f(i) > 0"], ["i_p - i = 1"], "i >= 1")
    assert out3["status"] == "unknown", out3


def test_insure_quotes_signed():
    src = chr(10).join(["contract R {",
                        "  function add(uint8 a, uint8 b) public pure returns (uint8) {",
                        "    require(a >= 200);", "    require(b >= 100);",
                        "    return a + b;", "  }", "}"])
    q = insure.quote(src, key="k", type_bits=8)
    assert q["quote"]["tier"] == "high", q
    assert q["quote"]["premium"] > 0
    assert insure.verify_quote(q, "k") is True
    forged = {"quote": dict(q["quote"], tier="low"), "signature": q["signature"]}
    assert insure.verify_quote(forged, "k") is False
    claims = insure.claims()
    assert "proven" in claims and "not_proven" in claims
    low = insure.quote("contract S { function f(uint8 a) public pure "
                       "returns (uint8) { return a + 1; } }", key="k",
                       type_bits=8)
    assert low["quote"]["tier"] == "low", low


def test_golfbench_broken_fixture():
    from pegrex.golfbench import golf
    d = tempfile.mkdtemp()
    p = os.path.join(d, "broken_cert.py")
    open(p, "w").write("raise SystemExit(1)\n")
    out = golf(p, None)
    assert out["status"] == "broken" and "error" in out, out


def test_golfbench_stale_baseline_honest():
    from pegrex.golfbench import golf
    d = tempfile.mkdtemp()
    p = os.path.join(d, "tiny.py")
    open(p, "w").write("assert 1 + 1 == 2\nprint('ok')\n")
    out = golf(p, os.path.join(d, "missing.json"))
    assert out["status"] == "baseline", out
