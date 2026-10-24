import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent


def test_m7_certificate():
    r = subprocess.run([sys.executable, "certs/m7_closed_form.py"], cwd=ROOT,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "M7 CERTIFICATE" in r.stdout


def test_detect_unit():
    sys.path.insert(0, str(ROOT))
    from pegrex.loops import detect, contract_closed_form, closed_form
    lp = detect(["s = s + i", "i = i + 1"], {"i": 1, "s": 0})
    assert lp is not None and (lp.index, lp.accum) == ("i", "s")
    assert contract_closed_form(lp, "n") == {
        "index_exit": "i = (n + 1)", "result": "((n * (n + 1)) // 2)"}
    # the closed form must match CONCRETE sums (Gauss), not just look right
    for n in (0, 1, 7, 100):
        assert eval(closed_form(lp, "n").__str__(), {"n": n}) \
            == sum(range(1, n + 1))
    # not a counting loop: missing accumulator
    assert detect(["i = i + 1"], {"i": 1, "s": 0}) is None
    # not a counting loop: non-unit step
    assert detect(["s = s + i", "i = i + 2"], {"i": 1, "s": 0}) is None
    # non-textbook inits still produce a closed form, verified concretely
    lp2 = detect(["s = s + i", "i = i + 1"], {"i": 0, "s": 5})
    for m in (0, 1, 9):
        assert eval(str(closed_form(lp2, "m")), {"m": m}) == 5 + sum(range(0, m + 1))


def test_lua_assign_render():
    sys.path.insert(0, str(ROOT))
    from pegrex.summaries import render_lua
    from pegrex.peg import Node
    a = Node("Assign", 0, 0, [Node("Id", 0, 0, ["s"]),
                              Node("BinaryOp", 0, 0,
                                   [Node("Id", 0, 0, ["s"]), "add",
                                    Node("Id", 0, 0, ["i"])])])
    assert render_lua(a) == "s = s + i"
