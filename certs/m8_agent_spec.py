#!/usr/bin/env python
"""M8: machine-readable agent specifications survive a strict JSON round trip."""
import json
import pathlib
import sys
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pegrex.specs import AgentReport, PathReport, PreprocessSpec

report = AgentReport(
    language="python", entrypoint="abs",
    preprocess=PreprocessSpec(language="python"),
    paths=[PathReport(path_id=0, blocks=[0, 1], constraints=["x >= 0"],
                      satisfiable=True, result="x")],
)
encoded = report.to_agent_json()
decoded = AgentReport.model_validate(json.loads(encoded))
assert decoded == report
assert json.loads(encoded)["paths"][0]["result"] == "x"
print("M8 OK: agent report schema and path outcome round trip")
