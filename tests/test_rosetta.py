import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest

from pegrex.rosetta import RosettaError, equivalence

PY_FACT = ("def fact(n):\n"
           "    if n == 0:\n"
           "        return 1\n"
           "    else:\n"
           "        return n * fact(n - 1)\n")
C_FACT = ("int fact(int n) {\n"
          "  if (n == 0) {\n"
          "    return 1;\n"
          "  } else {\n"
          "    return n * fact(n - 1);\n"
          "  }\n"
          "}\n")
GO_FACT = ("func fact(n int) int {\n"
           "\tif n == 0 {\n"
           "\t\treturn 1\n"
           "\t} else {\n"
           "\t\treturn n * fact(n - 1)\n"
           "\t}\n"
           "}\n")


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return p


def test_three_way_equivalent(tmp_path):
    pytest.importorskip("tree_sitter", reason="cross-language equivalence requires optional parser dependencies")
    pytest.importorskip("tree_sitter_c", reason="C frontend is optional")
    pytest.importorskip("tree_sitter_go", reason="Go frontend is optional")
    _write(tmp_path, "fact.py", PY_FACT)
    _write(tmp_path, "fact.c", C_FACT)
    _write(tmp_path, "fact.go", GO_FACT)
    spec = tmp_path / "spec.json"
    spec.write_text(json.dumps({
        "name": "fact",
        "variants": [{"language": "python", "source": "fact.py"},
                     {"language": "c", "source": "fact.c"},
                     {"language": "go", "source": "fact.go"}]}))
    out = equivalence(str(spec))          # relative sources resolve vs spec dir
    assert out["n_ways"] == "equivalent"
    assert out["refusals"] == []
    assert len(out["pairs"]) == 6
    assert all(p["verdict"] == "equivalent" for p in out["pairs"])


def test_counterexample_quotes_both_sides(tmp_path):
    a = _write(tmp_path, "a.py", PY_FACT)
    b = _write(tmp_path, "b.py", PY_FACT.replace("n == 0", "n == 1"))
    out = equivalence({"name": "neg", "variants": [
        {"language": "python", "source": str(a)},
        {"language": "python", "source": str(b)}]})
    assert out["n_ways"] == "counterexample"
    offenders = [p for p in out["pairs"] if p["verdict"] == "counterexample"]
    assert offenders
    for p in offenders:
        assert p["detail"]["contracts"]["a"]
        assert p["detail"]["contracts"]["b"]
        assert p["detail"]["constraints"]["a"] != p["detail"]["constraints"]["b"]


def test_single_variant_refused_loudly():
    with pytest.raises(RosettaError):
        equivalence({"name": "x", "variants": [
            {"language": "python", "source": "fact.py"}]})


def test_unknown_language_named_in_refusal(tmp_path):
    a = _write(tmp_path, "a.py", PY_FACT)
    out = equivalence({"name": "x", "variants": [
        {"language": "python", "source": str(a)},
        {"language": "cobol-ish", "source": "absval.cob"}]})
    assert out["n_ways"] == "refused"
    assert all(p["verdict"] == "refused" for p in out["pairs"])
    assert any("cobol-ish" in r for r in out["refusals"])


def test_parse_failure_quoted(tmp_path):
    a = _write(tmp_path, "a.py", PY_FACT)
    bad = _write(tmp_path, "bad.c", "int f(int a) { return a @@ 3; }\n")
    out = equivalence({"name": "p", "variants": [
        {"language": "python", "source": str(a)},
        {"language": "c", "source": str(bad)}]})
    assert out["n_ways"] == "refused"
    assert out["refusals"] and "parse failure" in out["refusals"][0]


def test_entry_variants_expand_calls(tmp_path):
    c = _write(tmp_path, "chain.c",
               "int clamp(int x) {\n  if (x < 0) { return 0; } else { return x; }\n}"
               "\nint clamp1(int y) {\n  return clamp(y) + 1;\n}"
               "\nint f(int n) {\n  return clamp1(n) * 2;\n}\n")
    py = _write(tmp_path, "chain.py",
                "def clamp(x):\n    if x < 0:\n        return 0\n    return x\n"
                "\n\ndef clamp1(y):\n    return clamp(y) + 1\n"
                "\n\ndef f(n):\n    return clamp1(n) * 2\n")
    params = {"clamp": "x", "clamp1": "y", "f": "n"}
    out = equivalence({"name": "chain", "variants": [
        {"language": "python", "source": str(py), "entry": "f", "params": params},
        {"language": "c", "source": str(c), "entry": "f", "params": params}]})
    assert out["n_ways"] == "equivalent", out


def test_entry_variant_unsupported_language_named(tmp_path):
    a = _write(tmp_path, "a.py", PY_FACT)
    go = _write(tmp_path, "a.go",
                "func fact(n int) int {\n\tif n == 0 {\n\t\treturn 1\n\t}\n"
                "\treturn n\n}\n")
    out = equivalence({"name": "g", "variants": [
        {"language": "python", "source": str(a)},
        {"language": "go", "source": str(go), "entry": "fact"}]})
    assert out["n_ways"] == "refused"
    assert any("go" in r for r in out["refusals"])
