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

from pegrex.benchmark import CASES, run_benchmark
from pegrex.marketplace import install, sign_manifest, verify_manifest
from pegrex.trainer import export_pairs, load_pairs

KEY = "k"
PACK = {"name": "p", "version": "1", "rules": ["r1", "r2"]}


def test_benchmark_perfect_on_real_verifier():
    out = run_benchmark()
    assert out["score"] == 1.0 and out["false_accept_rate"] == 0.0


def test_benchmark_deterministic():
    a, b = run_benchmark(), run_benchmark()
    assert [(r["name"], r["verified"]) for r in a["results"]] ==            [(r["name"], r["verified"]) for r in b["results"]]


def test_exporter_ships_only_verified():
    p = os.path.join(tempfile.mkdtemp(), "pairs.jsonl")
    counts = export_pairs(p)
    pairs = load_pairs(p)
    assert counts["exported"] == len(pairs) == 3
    assert counts["excluded"] == 3
    assert all(x["certificate"]["verified"] for x in pairs)


def test_signed_pack_installs():
    signed = sign_manifest(PACK, KEY)
    assert verify_manifest(signed, KEY)["ok"] is True
    assert install(signed, KEY)["status"] == "installed"


def test_tampered_wrongkey_unsigned_refused():
    signed = sign_manifest(PACK, KEY)
    tampered = dict(signed, rules=signed["rules"] + ["x"])
    assert verify_manifest(tampered, KEY)["ok"] is False
    assert verify_manifest(signed, "other")["ok"] is False
    assert verify_manifest({"rules": ["r"]}, KEY)["ok"] is False
    assert install(tampered, KEY)["status"] == "refused"
