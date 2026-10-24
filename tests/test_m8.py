import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent


def test_m8_agent_report():
    r = subprocess.run([sys.executable, "certs/m8_agent_spec.py"], cwd=ROOT,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    assert "M8 OK" in r.stdout


def test_agent_report_schema_roundtrip():
    sys.path.insert(0, str(ROOT))
    from pegrex.specs import AgentReport, PreprocessSpec
    rep = AgentReport(language="python", entrypoint="f",
                      preprocess=PreprocessSpec(language="python"))
    d = json.loads(rep.to_agent_json())
    assert d["language"] == "python" and d["z3"] == {}


def test_patterns_unit():
    sys.path.insert(0, str(ROOT))
    from pegrex.patterns import Pattern, match, scan
    from pegrex.peg import Node

    tree = Node("if_statement", 0, 10, [
        Node("condition", 0, 9, ["n == None"]),
        Node("block", 5, 10, []),
    ])
    rule = Pattern(node_type="condition", text=r"n\s*==\s*None",
                   id="eq-none")
    hits = list(scan(tree, [rule], "n == None"))
    assert len(hits) == 1 and hits[0][1].id == "eq-none"
    # positional child patterns + capture
    r2 = Pattern(node_type="if_statement",
                 children=[Pattern(node_type="condition")],
                 capture={"cond": 0})
    caps = match(tree, r2)
    assert caps["cond"].tag == "condition"
