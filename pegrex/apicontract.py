"""
apicontract — cross-language API contract checking

An OpenAPI schema is the shared contract; the Python server and the
Go client are each checked against it. Drift (missing endpoint,
renamed/retyped parameter, wrong arity) is reported, never guessed.
Agreement exists only when both sides match the schema."""

from __future__ import annotations

import ast
import json
import re

_TYPE_MAP = {"integer": "int", "number": "float", "string": "str", "boolean": "bool"}


def parse_openapi(spec) -> dict:
    """OpenAPI dict -> {operationId: {params: {name: type},
    required: [names], returns: type}}. Raises on non-dict input."""
    if isinstance(spec, str):
        spec = json.loads(spec)
    if not isinstance(spec, dict) or "paths" not in spec:
        raise ValueError("apicontract: not an OpenAPI document")
    out = {}
    for path, methods in spec.get("paths", {}).items():
        for method, op in (methods or {}).items():
            if not isinstance(op, dict):
                continue
            oid = op.get("operationId") or f"{method.upper()} {path}"
            params = {}
            required = []
            for prm in op.get("parameters", []) or []:
                sch = prm.get("schema", {})
                t = _TYPE_MAP.get(sch.get("type"), sch.get("type", "?"))
                params[prm["name"]] = t
                if prm.get("required"):
                    required.append(prm["name"])
            ret = "?"
            resp = (op.get("responses", {}) or {}).get("200", {})
            content = (resp.get("content", {}) or {}).get("application/json", {})
            sch = content.get("schema", {}) or {}
            if "$ref" in sch:
                ret = sch["$ref"].split("/")[-1]
            elif sch.get("type"):
                ret = _TYPE_MAP.get(sch["type"], sch["type"])
            out[oid] = {"params": params, "required": required, "returns": ret}
    return out


def check_python_server(src, spec) -> list:
    """Drift items between the schema and the Python implementation.

    A server op is a top-level def named like the operationId; parameter
    names and annotations are compared. Missing ops are drift."""
    contract = parse_openapi(spec)
    tree = ast.parse(src)
    fns = {}
    for node in tree.body:
        if isinstance(node, ast.FunctionDef):
            args = [a.arg for a in node.args.args]
            anns = {a.arg: (ast.unparse(a.annotation) if a.annotation else None)
                    for a in node.args.args}
            ret = ast.unparse(node.returns) if node.returns else None
            fns[node.name] = {"args": args, "anns": anns, "returns": ret}
    drift = []
    for oid, c in contract.items():
        if oid not in fns:
            drift.append({"op": oid, "kind": "missing-endpoint",
                          "side": "python-server"})
            continue
        f = fns[oid]
        for p, t in c["params"].items():
            if p not in f["args"]:
                drift.append({"op": oid, "kind": "missing-param",
                              "param": p, "side": "python-server"})
            else:
                ann = f["anns"].get(p)
                if ann and ann not in (t, f"{t} | None"):
                    drift.append({"op": oid, "kind": "type-mismatch",
                                  "param": p, "schema": t, "code": ann,
                                  "side": "python-server"})
        for p in c["required"]:
            if p not in f["args"]:
                drift.append({"op": oid, "kind": "missing-required",
                              "param": p, "side": "python-server"})
    return drift


_GO_FN = re.compile(r"func\s+(?:\(\w+\s+[*\w.]+\)\s+)?(\w+)\s*"
                    r"\(([^)]*)\)\s*([*\w.]+)?")


def check_go_client(src, spec) -> list:
    """Drift items between the schema and the Go client.

    Client ops are funcs named like operationId; Go types map:
    int->int, string->str, float64->float, bool->bool."""
    contract = parse_openapi(spec)
    go_map = {"int": "int", "string": "str", "float64": "float",
              "bool": "bool", "int64": "int"}
    fns = {}
    for m in _GO_FN.finditer(src):
        name, params_raw, ret = m.group(1), m.group(2) or "", m.group(3)
        params = {}
        for part in params_raw.split(","):
            part = part.strip()
            if not part:
                continue
            bits = part.split()
            if len(bits) == 2:
                params[bits[0]] = go_map.get(bits[1], bits[1])
        fns[name] = {"params": params,
                     "returns": go_map.get(ret, ret) if ret else None}
    drift = []
    for oid, c in contract.items():
        if oid not in fns:
            drift.append({"op": oid, "kind": "missing-endpoint",
                          "side": "go-client"})
            continue
        f = fns[oid]
        for p, t in c["params"].items():
            if p not in f["params"]:
                drift.append({"op": oid, "kind": "missing-param",
                              "param": p, "side": "go-client"})
            elif f["params"][p] != t:
                drift.append({"op": oid, "kind": "type-mismatch",
                              "param": p, "schema": t, "code": f["params"][p],
                              "side": "go-client"})
    return drift


def agreement(server_src, client_src, spec) -> dict:
    """Full cross-language agreement: BOTH sides checked against the schema.

    Verdict: agree only when both drift lists are empty. Every drift item
    names the side, the op, and the kind -- nothing is silently patched."""
    s = check_python_server(server_src, spec)
    g = check_go_client(client_src, spec)
    return {"agree": not s and not g,
            "drift": sorted(s + g, key=lambda d: (d["op"], d["side"]))}
