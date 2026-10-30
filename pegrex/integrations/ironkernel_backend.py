"""Bounded ironkernel expression execution and independent NumPy differential evidence."""
from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
import sys
import tempfile

from . import SCHEMA
from .common import MAX_OUTPUT_BYTES, read_json, run_argv, unknown_result, write_json

_ARITY = {"arg": 0, "const": 0, "neg": 1, "abs": 1, "sqrt": 1, "log": 1,
          "exp": 1, "log2": 1, "log10": 1, "sin": 1, "cos": 1, "tan": 1,
          "floor": 1, "ceil": 1, "add": 2, "sub": 2, "mul": 2, "div": 2,
          "pow": 2, "lt": 2, "le": 2, "gt": 2, "ge": 2, "eq": 2, "ne": 2,
          "atan2": 2, "min": 2, "max": 2, "where": 3}


def _finite_number(value) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def validate_expression(node, *, depth: int = 0, budget: list[int] | None = None) -> None:
    """Validate the public JSON expression DSL without evaluating it."""
    budget = [0] if budget is None else budget
    budget[0] += 1
    if budget[0] > 256 or depth > 32:
        raise ValueError("expression node/depth budget exhausted")
    if not isinstance(node, dict) or set(node) - {"op", "name", "value", "args"}:
        raise ValueError("malformed expression node")
    op = node.get("op")
    if op not in _ARITY:
        raise ValueError(f"unsupported ironkernel expression operation: {op!r}")
    args = node.get("args", [])
    if not isinstance(args, list) or len(args) != _ARITY[op]:
        raise ValueError(f"wrong argument count for {op}")
    if op == "arg":
        name = node.get("name")
        if not isinstance(name, str) or not name.isidentifier() or name.startswith("_"):
            raise ValueError("expression argument names must be public identifiers")
    if op == "const":
        value = node.get("value")
        if not _finite_number(value):
            raise ValueError("expression constants must be finite JSON numbers")
    for child in args:
        validate_expression(child, depth=depth + 1, budget=budget)


def expression_arguments(node) -> set[str]:
    names = {node["name"]} if node.get("op") == "arg" else set()
    for child in node.get("args", []):
        names.update(expression_arguments(child))
    return names


def validate_inputs(inputs, *, max_elements: int = 100_000) -> tuple[dict, int]:
    if not isinstance(inputs, dict) or not inputs or len(inputs) > 32:
        raise ValueError("inputs must contain between 1 and 32 named values")
    if not isinstance(max_elements, int) or isinstance(max_elements, bool) or not 1 <= max_elements <= 100_000:
        raise ValueError("max_elements must be between 1 and 100000")
    arrays, total = [], 0
    for name, value in inputs.items():
        if not isinstance(name, str) or not name.isidentifier() or name.startswith("_"):
            raise ValueError("input names must be public identifiers")
        if isinstance(value, bool):
            raise ValueError("Boolean inputs are outside the float64 contract")
        if isinstance(value, (int, float)):
            if not _finite_number(value):
                raise ValueError("input scalars must be finite")
        elif isinstance(value, list):
            if not 1 <= len(value) <= max_elements:
                raise ValueError("input array size exceeds its bound")
            if any(not _finite_number(row) for row in value):
                raise ValueError("input arrays must contain finite JSON numbers")
            arrays.append(len(value))
            total += len(value)
        else:
            raise ValueError("inputs must be finite scalars or flat numeric arrays")
    if not arrays or len(set(arrays)) != 1 or total > max_elements:
        raise ValueError("arrays must have equal lengths and fit the total element budget")
    return inputs, arrays[0]


def _canonical_request(expression, inputs) -> tuple[dict, str]:
    canonical = json.dumps({"expression": expression, "inputs": inputs},
                           sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return {"expression": expression, "inputs": inputs,
            "input_sha256": hashlib.sha256(canonical).hexdigest()}, hashlib.sha256(canonical).hexdigest()


def _execute(expression, inputs, *, timeout_ms: int, memory_mb: int) -> dict:
    request, identity = _canonical_request(expression, inputs)
    with tempfile.TemporaryDirectory(prefix="pegrex-ironkernel-") as directory:
        root = Path(directory)
        request_path, report_path = root / "request.json", root / "report.json"
        write_json(request_path, request)
        worker = Path(__file__).with_name("_ironkernel_worker.py")
        result = run_argv([sys.executable, str(worker), str(request_path), str(report_path)],
                          cwd=root, timeout_ms=timeout_ms, memory_mb=memory_mb,
                          sandbox=True)
        if not report_path.is_file():
            return unknown_result("ironkernel", "run", result["unknowns"] or [
                "ironkernel worker produced no report; optional dependency may be unavailable"],
                execution=result)
        report = read_json(report_path, max_bytes=MAX_OUTPUT_BYTES)
        if report.get("schema") != "pegrex.ironkernel-worker.v1":
            return unknown_result("ironkernel", "run", ["unsupported ironkernel worker report schema"],
                                  execution=result)
        if result["status"] != "completed" or report.get("error"):
            return unknown_result("ironkernel", "run",
                                  list(result["unknowns"]) + [str(report.get("error") or "worker failed")],
                                  execution=result)
        if report.get("input_sha256") != identity:
            return unknown_result("ironkernel", "run", ["ironkernel worker report identity mismatch"],
                                  execution=result)
        report["execution"] = result
        return report


def run_expression(expression: dict, inputs: dict, *, max_elements: int = 100_000,
                   timeout_ms: int = 10_000, memory_mb: int = 512) -> dict:
    """Execute a validated float64 expression outside the PegRex process."""
    try:
        validate_expression(expression)
        _, length = validate_inputs(inputs, max_elements=max_elements)
        if expression_arguments(expression) != set(inputs):
            raise ValueError("input names must exactly match expression arguments")
        result = _execute(expression, inputs, timeout_ms=timeout_ms, memory_mb=memory_mb)
        if result.get("status") == "unknown":
            return result
        observed = result.get("observed")
        if not isinstance(observed, list) or len(observed) != length:
            return unknown_result("ironkernel", "run", ["ironkernel result shape does not match the bounded input contract"])
        return {"schema": SCHEMA, "schema_version": 1, "backend": "ironkernel",
                "backend_version": result.get("backend_version"), "operation": "run",
                "status": "completed", "verdict": None, "candidate": False,
                "result": observed, "elements": length, "unknowns": result["execution"]["unknowns"],
                "assumptions": ["float64 elementwise semantics; flat equal-length arrays with scalar broadcast"],
                "execution": {"argv_only": True, "process_isolated": True,
                              "sandbox": False, "timeout_ms": timeout_ms}}
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as error:
        return unknown_result("ironkernel", "run", [f"{type(error).__name__}: {error}"])


def _nonfinite(row):
    return isinstance(row, dict) and set(row) == {"nonfinite"} and row["nonfinite"] in {"nan", "inf", "-inf"}


def _compare(observed, expected, *, atol: float, rtol: float) -> dict:
    if len(observed) != len(expected):
        return {"match": False, "index": 0, "unknowns": ["result lengths differ"]}
    for index, (left, right) in enumerate(zip(observed, expected)):
        if _nonfinite(left) or _nonfinite(right):
            if left == right and left.get("nonfinite") in {"inf", "-inf"}:
                continue
            return {"match": None, "index": index,
                    "unknowns": [f"non-finite result at index {index} requires an explicit domain/comparison policy"]}
        if isinstance(left, bool) or isinstance(right, bool) or not isinstance(left, (int, float)) or not isinstance(right, (int, float)):
            return {"match": None, "index": index, "unknowns": ["worker returned a non-numeric result"]}
        if not math.isclose(left, right, rel_tol=rtol, abs_tol=atol):
            return {"match": False, "index": index, "unknowns": []}
    return {"match": True, "index": None, "unknowns": []}


def _witness(inputs, index):
    return {name: (value[index] if isinstance(value, list) else value)
            for name, value in inputs.items()}


def differential(expression: dict, inputs: dict, *, max_elements: int = 100_000,
                 atol: float = 0.0, rtol: float = 0.0, timeout_ms: int = 10_000,
                 memory_mb: int = 512) -> dict:
    """Compare bounded observations; passing samples are never equivalence proofs."""
    try:
        validate_expression(expression)
        validate_inputs(inputs, max_elements=max_elements)
        if expression_arguments(expression) != set(inputs):
            raise ValueError("input names must exactly match expression arguments")
        if not all(_finite_number(value) and value >= 0 for value in (atol, rtol)):
            raise ValueError("atol and rtol must be finite nonnegative numbers")
        result = _execute(expression, inputs, timeout_ms=timeout_ms, memory_mb=memory_mb)
        if result.get("status") == "unknown":
            result["operation"] = "differential"
            return result
        comparison = _compare(result["observed"], result["expected"], atol=atol, rtol=rtol)
        base = {"schema": SCHEMA, "schema_version": 1, "backend": "ironkernel",
                "backend_version": result.get("backend_version"), "operation": "differential",
                "candidate": False, "input_sha256": result["input_sha256"],
                "claim": "bounded float64 expression equivalence under the recorded comparison policy",
                "comparison": {"atol": atol, "rtol": rtol}, "artifacts": [], "assumptions": []}
        if comparison["match"] is None:
            return base | {"status": "unknown", "verdict": "unknown",
                           "unknowns": comparison["unknowns"]}
        if comparison["match"] is False:
            index = comparison["index"]
            # A second independent process is required before confirming a witness.
            replay = _execute(expression, inputs, timeout_ms=timeout_ms, memory_mb=memory_mb)
            if replay.get("status") == "unknown":
                return base | {"status": "unknown", "verdict": "unknown",
                               "unknowns": ["mismatch replay was unavailable"]}
            replay_comparison = _compare(replay["observed"], replay["expected"], atol=atol, rtol=rtol)
            if replay_comparison["match"] is not False or replay_comparison["index"] != index or replay["observed"] != result["observed"]:
                return base | {"status": "unknown", "verdict": "unknown",
                               "unknowns": ["differential mismatch was not reproducible"]}
            return base | {"status": "refuted", "verdict": "refuted", "unknowns": [],
                           "observations_match": False,
                           "counterexample": {"confirmed": True, "index": index,
                               "inputs": _witness(inputs, index), "observed": result["observed"][index],
                               "expected": result["expected"][index], "replayed": True}}
        return base | {"status": "passed", "verdict": "unknown", "observations_match": True,
                       "unknowns": ["matching bounded differential observations do not prove general semantic equivalence"]}
    except (OSError, UnicodeError, ValueError, TypeError, json.JSONDecodeError) as error:
        return unknown_result("ironkernel", "differential", [f"{type(error).__name__}: {error}"])
