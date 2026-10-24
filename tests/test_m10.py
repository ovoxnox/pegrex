import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent


def test_m10_complex_certificate():
    r = subprocess.run([sys.executable, "certs/m10_complex.py"], cwd=ROOT,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "M10 CERTIFICATE" in r.stdout
    assert "(n * (n + 1))" in r.stdout


def test_compound_condition():
    sys.path.insert(0, str(ROOT))
    import pipeline
    parse, tagspec, make_cond = pipeline.python_frontend()
    src = ("def f(n):\n"
           "    if n > 0 and n < 10:\n"
           "        return 1\n"
           "    return 0\n")
    body = parse(src)
    assert body is not None
    cfg = __import__("pegrex.cfg", fromlist=["CFGBuilder"]).CFGBuilder(tagspec).build(body)
    cond = make_cond(src)
    texts = []
    for dst, e in cfg.successors(0):
        base = e.cond[0] if isinstance(e.cond, tuple) else e.cond
        texts.append(str(cond(base)))
    assert any("and" in c for c in texts), texts


def test_assignment_renderer():
    sys.path.insert(0, str(ROOT))
    from pegrex.assign import render_assignment
    from pegrex.peg import Node
    aug = Node("augmented_assignment", 0, 9, [])
    assert render_assignment(aug, "s += i") == "s = s + i"
    plain = Node("assignment", 0, 9, [])
    assert render_assignment(plain, "i = i + 1") == "i = i + 1"
