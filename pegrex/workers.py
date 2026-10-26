"""Resource-limited subprocess workers for hostile source and grammar inputs.

This is process/resource isolation, not a claim of container or network
sandboxing. Source is parsed as data and is never executed by the worker.
"""
from __future__ import annotations

import json
import math
import os
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from .schema import unknown_document
from .sandbox import sandbox_available

WORKER_SCHEMA = "pegrex.analyzer-worker.v1"
_WORKER = r'''
import json, sys
sys.path.insert(0, sys.argv[1])
def unknown(reason, details=None):
    return {"schema": "pegrex.analyzer-worker.v1", "status": "unknown",
            "result": None, "unknowns": [{"status": "unknown", "reason": reason,
                                           "details": details or {}}]}
def main():
    try:
        payload = json.loads(sys.stdin.buffer.read(2_100_000))
        source = payload["source"]
        kind = payload["analysis"]
        if not isinstance(source, str) or len(source.encode("utf-8")) > 2_000_000:
            raise ValueError("source input limit exceeded")
        if kind == "ssa":
            from pegrex.ssa import build_ssa
            result = build_ssa(source)
        elif kind == "effects":
            from pegrex.effects import infer_effects
            result = infer_effects(source)
        elif kind in {"taint", "secrets"}:
            from pegrex.flow import analyze_source, analyze_secrets
            result = analyze_secrets(source) if kind == "secrets" else analyze_source(source)
        elif kind == "grammar":
            from pegrex import compile_grammar
            from pegrex.gramir import lift_grammar, to_dsl
            _, rules = compile_grammar(source)
            result = {"rules": {name: to_dsl(ir) for name, ir in lift_grammar(rules).items()}}
        else:
            raise ValueError("unsupported worker analysis")
        print(json.dumps({"schema": "pegrex.analyzer-worker.v1", "status": "ok",
                          "result": result, "unknowns": []}, sort_keys=True))
    except Exception as error:
        print(json.dumps(unknown("worker-analysis-failed",
                                 {"type": type(error).__name__, "message": str(error)[:500]})))
main()
'''


def _limits(timeout_ms, memory_mb):
    import resource

    def apply():
        """Implement apply with the module's explicit API and failure semantics."""
        resource.setrlimit(resource.RLIMIT_CPU, (max(1, math.ceil(timeout_ms / 1000)),) * 2)
        resource.setrlimit(resource.RLIMIT_AS, (memory_mb * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_NOFILE, (32, 32))
        resource.setrlimit(resource.RLIMIT_FSIZE, (8_000_000, 8_000_000))
    return apply


def _unknown(reason, **details):
    return {"schema": WORKER_SCHEMA, "status": "unknown", "result": None,
            "unknowns": [unknown_document(reason, details=details)]}


def run_analyzer_worker(source: str, *, analysis="ssa", timeout_ms=5_000,
                        memory_mb=256, output_limit=8_000_000) -> dict:
    """Implement run analyzer worker with the module's explicit API and failure semantics."""
    if not isinstance(source, str) or len(source.encode("utf-8")) > 2_000_000:
        return _unknown("input-limit-exceeded", limit=2_000_000)
    if not sandbox_available() or os.name != "posix":
        return _unknown("resource-isolation-unavailable", platform=os.name)
    package_root = str(Path(__file__).resolve().parent.parent)
    payload = json.dumps({"source": source, "analysis": analysis}).encode("utf-8")
    with tempfile.TemporaryDirectory() as directory:
        output_path = Path(directory) / "result.json"
        with output_path.open("wb") as output:
            try:
                process = subprocess.Popen(
                    [sys.executable, "-I", "-S", "-c", _WORKER, package_root],
                    stdin=subprocess.PIPE, stdout=output, stderr=subprocess.STDOUT,
                    cwd=directory, env={}, start_new_session=True,
                    preexec_fn=_limits(timeout_ms, memory_mb))
            except OSError as error:
                return _unknown("worker-spawn-failed", message=str(error))
            try:
                process.communicate(payload, timeout=timeout_ms / 1000)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
                return _unknown("worker-timeout", timeout_ms=timeout_ms)
        if output_path.stat().st_size > output_limit:
            return _unknown("worker-output-limit", limit=output_limit)
        text = output_path.read_text(encoding="utf-8", errors="replace")
    if process.returncode != 0:
        return _unknown("worker-crashed", returncode=process.returncode,
                        evidence=text[-500:])
    try:
        report = json.loads(text.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return _unknown("worker-invalid-output", evidence=text[-500:])
    if report.get("schema") != WORKER_SCHEMA:
        return _unknown("worker-invalid-schema")
    report["worker"] = {"argv_only": True, "resource_limits": True,
                        "empty_environment": True, "source_executed": False,
                        "isolation_scope": "process-and-rlimits-not-container"}
    return report


def analyze_source_isolated(source: str, *, analysis="ssa", **limits) -> dict:
    """Implement analyze source isolated with the module's explicit API and failure semantics."""
    return run_analyzer_worker(source, analysis=analysis, **limits)


def compile_grammar_isolated(grammar: str, **limits) -> dict:
    """Implement compile grammar isolated with the module's explicit API and failure semantics."""
    return run_analyzer_worker(grammar, analysis="grammar", **limits)
