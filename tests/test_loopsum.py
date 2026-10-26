import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

import pytest

from pegrex.loopsum import LoopSumError, summarize

SUM_TO = """\
def sum_to(n):
    s = 0
    i = 1
    while i <= n:
        s = s + i
        i = i + 1
    return s
"""


def test_proved_full_summary():
    r = summarize(SUM_TO)
    assert r["verdict"] == "proved"
    assert "i >= 1" in r["invariant"]
    # i <= n + 1 is not an entry invariant when n is negative and the loop
    # is skipped; initiation must not assume the loop guard.
    assert "i <= n + 1" not in r["invariant"]
    assert r["ranking"] == "n - i + 1"
    assert r["closed_form"]["result"] == "((n * (n + 1)) // 2)"
    assert r["evidence"][0]["violations"] == 0


def test_closed_form_matches_concrete_runs():
    r = summarize(SUM_TO)
    ns = {}
    exec(SUM_TO, ns)
    for n in (0, 1, 5, 42):
        assert ns["sum_to"](n) == eval(r["closed_form"]["result"], {"n": n})


def test_no_counter_is_summary_only_or_refused():
    src = ("def drain(n):\n    s = 0\n    while s <= n:\n"
           "        s = s + n\n    return s\n")
    r = summarize(src)
    assert r["verdict"] in ("summary-only", "refused")
    if r["verdict"] == "summary-only":
        assert r["ranking"] is None
        assert "termination unproven" in r["reason"]


def test_nonlinear_guard_refuses():
    with pytest.raises(LoopSumError, match="linear fragment"):
        summarize("def f(x):\n    while x * x < 16:\n        x = x + 1\n"
                  "    return x\n")


def test_nonlinear_body_refuses():
    with pytest.raises(LoopSumError, match="outside the fragment"):
        summarize("def f(x):\n    i = 0\n    while i < x:\n"
                  "        i = i * 2\n    return i\n")


def test_function_calls_in_body_refuse():
    with pytest.raises(LoopSumError, match="outside the fragment"):
        summarize("def f(x):\n    i = 0\n    while i < x:\n"
                  "        i = i + abs(1)\n    return i\n")


def test_no_loop_refuses():
    with pytest.raises(LoopSumError, match="no while loop"):
        summarize("def f(x):\n    return x\n")


def test_strict_guard_normalized():
    src = ("def sum_below(n):\n    s = 0\n    i = 0\n"
           "    while i < n:\n        s = s + i\n        i = i + 1\n"
           "    return s\n")
    r = summarize(src)
    assert r["verdict"] in ("proved", "summary-only")
    ns = {}
    exec(src, ns)
    if r["closed_form"]:
        for n in (0, 3, 10):
            assert ns["sum_below"](n) == eval(r["closed_form"]["result"],
                                              {"n": n})
