"""OpenAPI old/new round-trip compatibility and generated client/server stubs."""
from __future__ import annotations

import ast
import json

from .apicontract import check_go_client, check_python_server, parse_openapi

SCHEMA = "pegrex.api-round-trip.v1"


def generate_api_stubs(spec) -> dict:
    """Generate deterministic Python server and Go client contract stubs."""
    contract = parse_openapi(spec)
    python = []
    go = []
    for operation, row in sorted(contract.items()):
        params = sorted(row["params"])
        annotations = ", ".join(f"{name}: {row['params'][name]}" for name in params)
        returns = row["returns"] if row["returns"] != "?" else "object"
        python.append(f"def {operation}({annotations}) -> {returns}:")
        python.append("    raise NotImplementedError(\"generated contract stub\")")
        python.append("")
        go_params = ", ".join(f"{name} {_go_type(row['params'][name])}" for name in params)
        go.append(f"func {operation}({go_params}) {_go_type(returns)} {{")
        go.append("    panic(\"generated contract stub\")")
        go.append("}")
        go.append("")
    return {"python_server": "\n".join(python), "go_client": "\n".join(go),
            "operations": sorted(contract)}


def _go_type(value):
    return {"int": "int", "float": "float64", "str": "string",
            "bool": "bool"}.get(value, "interface{}")


def _runtime(old_invoker, new_invoker, operations, cases):
    if old_invoker is None or new_invoker is None:
        return {"verdict": "unknown", "cases": [],
                "unknowns": ["old and new runtime invokers are required for round-trip proof"]}
    by_operation = {operation: [] for operation in operations}
    for case in cases:
        if case.get("operation") in by_operation:
            by_operation[case["operation"]].append(case)
    rows, unknowns = [], []
    for operation in operations:
        if not by_operation[operation]:
            unknowns.append(f"no runtime round-trip case for {operation}")
    for index, case in enumerate(cases):
        operation = case.get("operation")
        if operation not in by_operation:
            unknowns.append(f"runtime case {index} names an unknown operation")
            continue
        params = case.get("params") or {}
        try:
            before = old_invoker(operation, params)
            after = new_invoker(operation, params)
            match = json.dumps(before, sort_keys=True, separators=(",", ":")) == json.dumps(
                after, sort_keys=True, separators=(",", ":"))
            rows.append({"operation": operation, "params": params,
                         "match": match, "before": before, "after": after,
                         "verdict": "proved" if match else "refuted"})
        except Exception as error:
            rows.append({"operation": operation, "params": params,
                         "verdict": "unknown", "error": str(error)})
            unknowns.append(f"runtime case {index} failed: {error}")
    verdict = ("refuted" if any(row["verdict"] == "refuted" for row in rows) else
               "unknown" if unknowns or any(row["verdict"] == "unknown" for row in rows) else "proved")
    return {"verdict": verdict, "cases": rows, "unknowns": unknowns}


def check_round_trip(spec, *, old_server=None, new_server=None,
                     old_client=None, new_client=None, old_invoker=None,
                     new_invoker=None, cases=()) -> dict:
    """Check both API generations and execute explicit old/new runtime cases.

    Generated stubs are always returned for tooling. Static agreement alone is
    not a round-trip proof: every operation needs a matching runtime case.
    """
    try:
        stubs = generate_api_stubs(spec)
        python_stub = stubs["python_server"]
        go_stub = stubs["go_client"]
        ast.parse(python_stub or "\n")
        generations = (("old_server", old_server), ("new_server", new_server),
                       ("old_client", old_client), ("new_client", new_client))
        sources = {}
        for name, supplied in generations:
            fallback = python_stub if name.endswith("server") else go_stub
            sources[name] = supplied if supplied is not None else fallback
        static = {}
        for name, source in sources.items():
            checker = check_python_server if name.endswith("server") else check_go_client
            static[name] = checker(source, spec)
        runtime = _runtime(old_invoker, new_invoker, stubs["operations"], cases)
        drift = [{"generation": side, **row} for side, rows in static.items() for row in rows]
        verdict = ("refuted" if drift or runtime["verdict"] == "refuted" else
                   "unknown" if runtime["verdict"] == "unknown" else "proved")
        return {"schema": SCHEMA, "schema_version": 1, "verdict": verdict,
                "compatible": verdict == "proved", "static_drift": drift,
                "runtime": runtime, "generated_stubs": stubs,
                "unknowns": list(runtime["unknowns"]),
                "scope": "declared OpenAPI operations and supplied runtime cases"}
    except Exception as error:
        return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown",
                "compatible": False, "unknowns": [f"round-trip check failed: {type(error).__name__}: {error}"]}
