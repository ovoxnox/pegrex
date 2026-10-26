import pytest

from pegrex.effects import CATEGORIES, infer_effects, transitive_effects


SOURCE = '''
import random
import requests
VALUE = 0

def fetch(path):
    response = requests.get(path)
    return response.text

def work(path):
    global VALUE
    items = []
    items.append(random.random())
    VALUE = len(items)
    print(fetch(path))
    with open(path, "w") as stream:
        stream.write(str(VALUE))
    if VALUE > 2:
        raise ValueError(path)
'''


def test_explicit_effect_categories_and_mutation_scopes():
    report = infer_effects(SOURCE)
    work = report["functions"]["work"]
    assert set(CATEGORIES) - {"concurrency", "network", "process"} <= set(work["categories"])
    assert "network" not in work["categories"]  # inherited from fetch, not direct
    assert any(row["scope"] == "local" and "items" in row["action"]
               for row in work["effects"])
    assert any(row["scope"] == "external" and row["action"] == "assign:VALUE"
               for row in work["effects"])
    assert not work["pure"]


def test_transitive_effects_keep_provenance_and_cycles_incomplete():
    direct = {name: value for name, value in infer_effects(SOURCE)["functions"].items()}
    direct["recursive"] = {"effects": []}
    calls = {"work": ["fetch"], "fetch": [], "recursive": ["recursive"]}
    result = transitive_effects(direct, calls)
    assert any(row["origin"] == "inherited:fetch" and row["category"] == "network"
               for row in result["work"]["effects"])
    assert result["work"]["complete"] is True
    assert result["recursive"]["complete"] is False


def test_unsupported_language_has_unknown_coverage_not_empty_effects():
    with pytest.raises(NotImplementedError, match="unknown effect coverage"):
        infer_effects("int main() { return 0; }", "c")
