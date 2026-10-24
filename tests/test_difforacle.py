import pathlib
import random
import sys

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest

from pegrex import difforacle as d
from pegrex.difforacle import (DifforacleError, binary_result,
                               contract_result, safe_eval)


def test_seeded_run_agrees():
    res = d.run(seed=0, n=4, cc="cc", timeout=10)
    assert res["verdict"] == "agree", res["findings"]
    assert res["checked"] > 0
    assert res["findings"] == []


def test_contract_result_matches_binary():
    rng = random.Random(99)
    for _ in range(5):
        case = d.gen_case(rng)
        params = d._params_of(case["src"])
        for args in [[1] * len(params), [-3] * len(params),
                     list(range(1, len(params) + 1))]:
            assert binary_result("cc", case, args) == \
                contract_result(case, args), (case["src"], args)


def test_contract_result_three_valued():
    case = {"src": "int f(int a) {\n    return a * 5;\n}\n", "name": "f"}
    assert contract_result(case, [3]) == 15
    with pytest.raises(DifforacleError):
        contract_result(case, [3, 4])


def test_canary_is_classified():
    out = d.run_canary(cc="cc", timeout=10)
    assert out["classified"] in ("divergence", "agree", "refused")
    if out["classified"] == "divergence":
        assert out["finding"]["binary"] != out["finding"]["contract"]


def test_missing_compiler_refused():
    res = d.run(seed=0, n=2, cc="cc-does-not-exist", timeout=5)
    assert res["verdict"] == "refused"
    assert "cc-does-not-exist" in res["refusal"]


def test_generator_determinism():
    l1 = [d.gen_case(random.Random(7))["src"] for _ in range(8)]
    l2 = [d.gen_case(random.Random(7))["src"] for _ in range(8)]
    assert l1 == l2


def test_safe_eval_whitelist():
    assert safe_eval("(a + 3) * 2", {"a": 4}) == 14
    assert safe_eval("not (a = 2)", {"a": 5}) is True
    assert safe_eval("(not (a <= 1))", {"a": 0}) is False
    with pytest.raises(DifforacleError):
        safe_eval("__import__('os').system('true')", {})
    with pytest.raises(DifforacleError):
        safe_eval("a / 0", {"a": 1})


def test_gen_case_shape():
    case = d.gen_case(random.Random(1))
    assert set(case.keys()) >= {"src", "name"}
    assert "return" in case["src"]
    assert "/" not in case["src"]                  # no division: UB-free
    assert case["src"].count("return") == 1        # single return
