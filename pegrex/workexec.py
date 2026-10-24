"""
workexec.py -- execute .work agents: each workflow step runs through its
declared executor on the engine (code -> contracts/analysis, rule -> secaudit,
slm -> the mini LM for prose steps).  The agent written in the DSL acts.
"""
from __future__ import annotations

import json
import pathlib

from .work import compile_work

EXECUTOR_KINDS = ("code", "rule", "ml", "slm")


def execute(work_path: str, target: str | None = None) -> dict:
    """Run a .work agent's workflow against an optional target source.

    Returns {step: result} per executed step."""
    spec = compile_work(work_path)
    steps = spec.get("workflow_steps", [])
    executors = spec.get("executors", {})
    results = {}
    target = target or spec["preprocess"]["source_files"][0]
    for step in steps:
        kind = executors.get(step, "code")
        results[step] = _run_step(step, kind, target)
    return {"agent": spec["name"], "steps": results,
            "invariants": spec["postprocess"]["invariants"]}


def _run_step(step: str, kind: str, target: str):
    import sys as _sys
    root = pathlib.Path(__file__).resolve().parent.parent
    if str(root) not in _sys.path:
        _sys.path.insert(0, str(root))
    if kind == "rule":
        from tools.secaudit import audit
        return {"findings": len(audit(target))}
    if kind == "slm":
        from .mini_llm import NGramLM
        src = pathlib.Path(target).read_text()
        lm = NGramLM(n=3)
        lm.train(src)
        return {"perplexity": round(lm.perplexity(src[:200]), 2)}
    if kind in ("code", "ml"):
        try:
            from pegrex import api
            return {"contract_paths": len(api.contracts(target))}
        except Exception as e:
            return {"error": repr(e)[:100]}
    return {"error": f"unknown executor {kind!r}"}


if __name__ == "__main__":
    out = execute(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
    print(json.dumps(out, indent=1))
