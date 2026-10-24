import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

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

from pegrex.invmarket import (InvMarketError, MARKET_SECTION, claims,
                              discharge, import_invariants, publish_invariant,
                              quote)
from pegrex.registry import load_registry, publish as reg_publish

KEY = "test-market-key"


@pytest.fixture()
def market_reg(tmp_path):
    pkg = tmp_path / "mypkg"
    pkg.mkdir()
    (pkg / "clamp.py").write_text(
        "def clamp_nonneg(n):\n    if n < 0:\n        return 0\n    return n\n")
    reg = str(tmp_path / "registry.json")
    publish_invariant(reg, "mypkg", "clamp-nonneg", ["result >= 0"],
                      "witness: clamp.py", KEY)
    publish_invariant(reg, "mypkg", "clamp-ge-input", ["result >= n"],
                      "witness: clamp.py", KEY, price=2.5)
    return reg


def test_publish_proves_first_and_chains(market_reg):
    reg = load_registry(market_reg)
    entries = reg[MARKET_SECTION]["entries"]
    assert len(entries) == 2
    assert entries[0]["prev"] is None
    import hashlib
    from pegrex.attest import canonical_json
    assert entries[1]["prev"] == hashlib.sha256(
        canonical_json(entries[0]).encode()).hexdigest()
    assert entries[0]["signature"] and entries[1]["signature"]


def test_import_verifies_signatures_and_chain(market_reg):
    market = import_invariants(market_reg, key=KEY)
    assert len(market) == 2
    assert import_invariants(market_reg, package="mypkg", key=KEY) == market
    assert import_invariants(market_reg, package="absent", key=KEY) == []


def test_import_wrong_key_refused(market_reg):
    with pytest.raises(InvMarketError):
        import_invariants(market_reg, key="wrong-key")


def test_tampered_entry_refused_naming_it(market_reg, tmp_path):
    regj = load_registry(market_reg)
    regj[MARKET_SECTION]["entries"][0]["price"] = 999.0
    pathlib.Path(market_reg).write_text(json.dumps(regj))
    with pytest.raises(InvMarketError) as ei:
        import_invariants(market_reg, key=KEY)
    assert "clamp-nonneg" in str(ei.exc if hasattr(ei, "exc") else ei) \
        or "clamp-nonneg" in str(ei)


def test_unprovable_invariant_refused_naming_atom(market_reg):
    with pytest.raises(InvMarketError) as ei:
        publish_invariant(market_reg, "mypkg", "bogus", ["result <= -1"],
                          "w", KEY)
    msg = str(ei.value if hasattr(ei, "value") else ei)
    assert "result <= -1" in msg


def test_nonlinear_invariant_refused(market_reg):
    with pytest.raises(InvMarketError) as ei:
        publish_invariant(market_reg, "mypkg", "nl", ["n*n >= 0"], "w", KEY)
    assert "n*n >= 0" in str(ei.value if hasattr(ei, "value") else ei)


def test_missing_package_dir_refused(tmp_path):
    reg = str(tmp_path / "r.json")
    with pytest.raises(InvMarketError):
        publish_invariant(reg, "ghost", "x", ["result >= 0"], "w", KEY)


def test_discharge_proved_by_market(market_reg):
    market = import_invariants(market_reg, key=KEY)
    out = discharge(["result >= 0"], market)
    row = out["results"][0]
    assert row["verdict"] == "proved-by-market"
    assert row["discharged_by"] == "clamp-nonneg"
    assert out["discharged"] == 1


def test_discharge_var_var_obligation(market_reg):
    market = import_invariants(market_reg, key=KEY)
    out = discharge(["result >= n"], market)
    assert out["results"][0]["discharged_by"] == "clamp-ge-input"


def test_discharge_open_and_unknown(market_reg):
    market = import_invariants(market_reg, key=KEY)
    out = discharge(["n >= 0", "n*n >= 0"], market)
    assert out["results"][0]["verdict"] == "open"
    assert out["results"][1]["verdict"] == "unknown"
    assert out["results"][1]["reason"]


def test_quote_basis_says_heuristic(market_reg):
    market = import_invariants(market_reg, key=KEY)
    q = quote(market[0])
    assert q["price"] > 0
    assert "heuristic" in q["basis"] and "not a market price" in q["basis"]


def test_claims_honesty_manifest():
    c = claims()
    assert c["proven"] and c["not_proven"]
    assert any("not re-proof" in n for n in c["not_proven"])


def test_market_section_stays_registry_compatible(market_reg, tmp_path):
    # a plain registry publish still works in a file that has a market
    src = "def clamp_nonneg(n):\n    if n < 0:\n        return 0\n    return n\n"
    out = reg_publish("plainpkg", "1.0.0", {"a.py": src}, "k", market_reg)
    assert out["status"] == "published"
    reg = load_registry(market_reg)
    assert reg["plainpkg"]["version"] == "1.0.0"
    assert len(reg[MARKET_SECTION]["entries"]) == 2


def test_dict_form_package(tmp_path):
    reg = str(tmp_path / "r.json")
    pkg = {"__name__": "dictpkg",
           "clamp.py": "def clamp_nonneg(n):\n    if n < 0:\n        return 0\n    return n\n"}
    publish_invariant(reg, pkg, "inv", ["result >= 0"], "w", KEY)
    market = import_invariants(reg, key=KEY)
    assert market[0]["package"] == "dictpkg"
