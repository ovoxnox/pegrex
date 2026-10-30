#!/usr/bin/env python3
"""Infer stable top-level JSON result fields for registered legacy schema IDs.

This only upgrades envelope-only schemas where concrete result constructors are
visible in the Python AST. It deliberately does not guess nested object shapes;
those schemas are marked `inferred-top-level` until reviewed and strengthened.
"""
from __future__ import annotations

import ast
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
SCHEMA_RE = re.compile(r"pegrex\.(?:[A-Za-z0-9_-]+\.)+v\d+$")


def _infer(node):
    if isinstance(node, ast.Constant):
        if node.value is None: return {"type": "null"}
        if isinstance(node.value, bool): return {"type": "boolean"}
        if isinstance(node.value, int): return {"type": "integer"}
        if isinstance(node.value, float): return {"type": "number"}
        if isinstance(node.value, str): return {"type": "string"}
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        items = [_infer(item) for item in node.elts]
        merged = _merge_inferred(items)
        return {"type": "array", **({"items": merged} if merged else {})}
    if isinstance(node, (ast.ListComp, ast.SetComp, ast.GeneratorExp)):
        return {"type": "array"}
    if isinstance(node, ast.Dict):
        properties = {}
        required = []
        for key_node, value_node in zip(node.keys, node.values):
            if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                properties[key_node.value] = _infer(value_node)
                required.append(key_node.value)
        result = {"type": "object", "additionalProperties": True}
        if properties:
            result["properties"] = properties
            result["required"] = sorted(required)
        return result
    if isinstance(node, (ast.Compare, ast.BoolOp, ast.UnaryOp)):
        return {"type": "boolean"}
    if isinstance(node, ast.IfExp):
        left, right = _infer(node.body), _infer(node.orelse)
        if left and right:
            types = sorted(set((left.get("type") if isinstance(left.get("type"), str) else "") .split()) |
                            set((right.get("type") if isinstance(right.get("type"), str) else "").split()))
            if types: return {"type": types[0] if len(types) == 1 else types}
        return {}
    if isinstance(node, ast.Call):
        fn = ast.unparse(node.func)
        if fn in {"list", "tuple", "set", "sorted", "reversed"}: return {"type": "array"}
        if fn in {"dict", "vars"}: return {"type": "object"}
        if fn in {"str", "repr", "format"}: return {"type": "string"}
        if fn in {"int", "len", "sum"}: return {"type": "integer"}
        if fn in {"float"}: return {"type": "number"}
        if fn in {"bool", "all", "any", "isinstance"}: return {"type": "boolean"}
    return {}


def _merge_inferred(items):
    """Merge inferred schema fragments without asserting unsupported constraints."""
    items = [item for item in items if isinstance(item, dict) and item]
    if not items:
        return {}
    types = set()
    for item in items:
        typ = item.get("type")
        if isinstance(typ, str): types.add(typ)
        elif isinstance(typ, list): types.update(typ)
    result = {"type": sorted(types)[0] if len(types) == 1 else sorted(types)} if types else {}
    props = {}
    for item in items:
        for key, child in item.get("properties", {}).items():
            props.setdefault(key, []).append(child)
    if props:
        result["properties"] = {key: _merge_inferred(values) for key, values in sorted(props.items())}
        required_sets = [set(item.get("required", [])) for item in items if "properties" in item]
        if required_sets:
            common = set.intersection(*required_sets) if required_sets else set()
            if common: result["required"] = sorted(common)
        result["additionalProperties"] = True
    item_schemas = [item["items"] for item in items if isinstance(item.get("items"), dict)]
    if item_schemas:
        result["items"] = _merge_inferred(item_schemas)
    return result


def _schema_ids(tree):
    constants = {}
    for node in tree.body:
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if isinstance(value, ast.Constant) and isinstance(value.value, str) and SCHEMA_RE.fullmatch(value.value):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name): constants[target.id] = value.value
    return constants


def build(root: Path = ROOT) -> dict:
    from pegrex.schema import schema_catalog
    catalog = schema_catalog()
    observations: dict[str, list[dict[str, ast.AST]]] = {}
    source_paths = [path for path in root.rglob("*.py")
                    if not any(part in {"tests", "build", "dist", "__pycache__", "pegrex.egg-info"}
                               for part in path.relative_to(root).parts)]
    for path in sorted(source_paths):
        try: tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=str(path))
        except (OSError, SyntaxError): continue
        constants = _schema_ids(tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict): continue
            keys = {}
            schema_id = None
            for key_node, value_node in zip(node.keys, node.values):
                if isinstance(key_node, ast.Constant) and key_node.value == "schema":
                    if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
                        schema_id = value_node.value
                    elif isinstance(value_node, ast.Name):
                        schema_id = constants.get(value_node.id)
                if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                    keys[key_node.value] = value_node
            if schema_id in catalog and "x-peg-rex-validation-level" in catalog[schema_id]:
                observations.setdefault(schema_id, []).append(keys)
    upgraded = {}
    for schema_id, schema in catalog.items():
        if "x-peg-rex-validation-level" not in schema: continue
        rows = observations.get(schema_id, [])
        properties = {"schema": {"const": schema_id}}
        all_keys = set().union(*(set(row) for row in rows)) if rows else set()
        for key in sorted(all_keys - {"schema"}):
            inferred = [_infer(row[key]) for row in rows if key in row]
            properties[key] = _merge_inferred(inferred) or {}
        common = set(rows[0]) if rows else {"schema"}
        for row in rows[1:]: common.intersection_update(row)
        required = sorted(common | {"schema"})
        level = "inferred-top-level" if len(properties) > 1 else "envelope-only; nested contract pending stabilization"
        upgraded[schema_id] = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"pegrex:{schema_id}:schema",
            "title": f"PegRex public result: {schema_id}",
            "type": "object", "required": required, "properties": properties,
            "additionalProperties": True,
            "x-peg-rex-validation-level": level,
        }
    manual = {
        "pegrex.agent-evidence.v1": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "pegrex:pegrex.agent-evidence.v1:schema",
            "title": "Typed agent evidence envelope", "type": "object",
            "required": ["schema", "tool", "verdict", "data", "unknowns", "provenance"],
            "properties": {
                "schema": {"const": "pegrex.agent-evidence.v1"},
                "tool": {"type": "string", "minLength": 1},
                "verdict": {"enum": ["proved", "refuted", "unknown", "ok"]},
                "data": {"type": "object"},
                "unknowns": {"type": "array", "items": {"type": ["string", "object"]}},
                "provenance": {"type": "object"}},
            "additionalProperties": True},
        "pegrex.agent-role-evidence.v1": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "pegrex:pegrex.agent-role-evidence.v1:schema",
            "title": "Independent agent role evidence", "type": "object",
            "required": ["schema", "schema_version", "role", "verdict", "data", "unknowns"],
            "properties": {
                "schema": {"const": "pegrex.agent-role-evidence.v1"},
                "schema_version": {"const": 1},
                "role": {"enum": ["candidate-generation", "patch-generation",
                                   "counterexample-search", "independent-checking"]},
                "verdict": {"enum": ["proved", "refuted", "unknown", "ok"]},
                "data": {"type": "object"},
                "unknowns": {"type": "array", "items": {"type": "string"}}},
            "additionalProperties": True},
        "pegrex.multi-agent-change.v1": {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "pegrex:pegrex.multi-agent-change.v1:schema",
            "title": "Proof-gated multi-agent change result", "type": "object",
            "required": ["schema", "schema_version", "status", "applied", "verdict",
                         "roles", "unknowns", "patch_gate"],
            "properties": {
                "schema": {"const": "pegrex.multi-agent-change.v1"},
                "schema_version": {"const": 1},
                "status": {"enum": ["applied", "rejected"]},
                "applied": {"type": "boolean"}, "approved": {"type": "boolean"},
                "verdict": {"enum": ["proved", "refuted", "unknown"]},
                "roles": {"type": "array", "items": {"type": "object"}},
                "unknowns": {"type": "array", "items": {"type": "string"}},
                "patch_gate": {"type": ["object", "null"]},
                "independence": {"type": "object"}},
            "additionalProperties": True},
        "pegrex.core-engine.v1": {
            "$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "pegrex:pegrex.core-engine.v1:schema",
            "title": "PegRex core engine operation manifest", "type": "object",
            "required": ["schema", "api_version", "operations", "error_policy"],
            "properties": {"schema": {"const": "pegrex.core-engine.v1"}, "api_version": {"type": "string"},
                           "operations": {"type": "object"}, "error_policy": {"type": "string"}},
            "additionalProperties": True},
        "pegrex.integration-request.v1": {
            "$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "pegrex:pegrex.integration-request.v1:schema",
            "title": "PegRex optional integration request", "type": "object",
            "required": ["schema", "operation"],
            "properties": {"schema": {"const": "pegrex.integration-request.v1"}, "schema_version": {"type": "integer", "const": 1},
                           "operation": {"type": "string", "minLength": 1}, "arguments": {"type": "object"}},
            "additionalProperties": False},
        "pegrex.integration-result.v1": {
            "$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "pegrex:pegrex.integration-result.v1:schema",
            "title": "PegRex optional integration result", "type": "object",
            "required": ["schema", "schema_version", "backend", "operation", "status", "verdict", "candidate", "artifacts", "unknowns", "assumptions"],
            "properties": {"schema": {"const": "pegrex.integration-result.v1"}, "schema_version": {"type": "integer", "const": 1},
                           "backend": {"type": "string"}, "operation": {"type": "string"},
                           "status": {"type": "string"}, "verdict": {"enum": ["proved", "refuted", "unknown"]},
                           "candidate": {"type": "boolean"}, "artifacts": {"type": "array", "items": {"type": "object"}},
                           "unknowns": {"type": "array", "items": {"type": "string"}},
                           "assumptions": {"type": "array", "items": {"type": "string"}}, "execution": {"type": "object"}},
            "additionalProperties": True},
        "pegrex.neural-codegen-backend.v1": {
            "$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "pegrex:pegrex.neural-codegen-backend.v1:schema",
            "title": "Neural code-generation backend report", "type": "object",
            "required": ["schema", "status"],
            "properties": {"schema": {"const": "pegrex.neural-codegen-backend.v1"},
                           "status": {"enum": ["generated", "error", "unknown"]}, "endpoints": {"type": ["integer", "null"]},
                           "error": {"type": ["string", "null"]}, "unknowns": {"type": "array", "items": {"type": "string"}}},
            "additionalProperties": True},
        "pegrex.health-dispositions.v1": {
            "$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "pegrex:pegrex.health-dispositions.v1:schema",
            "title": "PegRex health disposition policy", "type": "object",
            "required": ["schema", "report_sha256", "policies", "tasks"],
            "properties": {"schema": {"const": "pegrex.health-dispositions.v1"},
                           "report_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
                           "policies": {"type": "object", "additionalProperties": {"type": "object",
                               "required": ["status", "rationale", "evidence"],
                               "properties": {"status": {"type": "string"}, "rationale": {"type": "string"},
                                              "evidence": {"type": "array", "items": {"type": "string"}}}}},
                           "tasks": {"type": "object", "additionalProperties": {"type": "string"}}},
            "additionalProperties": False},
        "pegrex.harness-policy-tests.v1": {
            "$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "pegrex:pegrex.harness-policy-tests.v1:schema",
            "title": "PegRex agent harness policy mutation suite", "type": "object",
            "required": ["schema", "mutation_report_schema", "suite_schema", "controls", "verdict", "mutation_verdict", "safe_baseline_allowed", "expected_mutation_status", "expectation_failures", "unknowns"],
            "properties": {"schema": {"const": "pegrex.harness-policy-tests.v1"},
                           "mutation_report_schema": {"const": "pegrex.analyzer-mutation.v1"},
                           "suite_schema": {"const": "pegrex.harness-policy-tests.v1"},
                           "controls": {"type": "array", "items": {"type": "object"}},
                           "verdict": {"enum": ["proved", "refuted", "unknown"]},
                           "mutation_verdict": {"enum": ["proved", "refuted", "unknown"]},
                           "safe_baseline_allowed": {"type": "boolean"},
                           "expected_mutation_status": {"type": "object"},
                           "expectation_failures": {"type": "array", "items": {"type": "string"}},
                           "unknowns": {"type": "array", "items": {"type": "string"}},
                           "killed": {"type": "integer"}, "survived": {"type": "integer"}},
            "additionalProperties": True},
        "pegrex.sandboxed-differential.v1": {
            "$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "pegrex:pegrex.sandboxed-differential.v1:schema",
            "title": "Sandboxed differential test result", "type": "object",
            "required": ["schema", "status", "verdict", "allowed", "unknowns"],
            "properties": {"schema": {"const": "pegrex.sandboxed-differential.v1"},
                           "status": {"enum": ["unknown", "different", "passed"]},
                           "verdict": {"enum": ["proved", "refuted", "unknown"]}, "allowed": {"type": "boolean"},
                           "observations_match": {"type": "boolean"}, "before": {"type": ["object", "null"]},
                           "after": {"type": ["object", "null"]}, "counterexample": {"type": ["object", "null"]},
                           "unknowns": {"type": "array", "items": {"type": "string"}},
                           "containerized": {"type": "boolean"}},
            "additionalProperties": True},
    }
    # Keep explicitly curated schemas synchronized with the runtime catalog.
    # Inferred schemas are emitted only where no reviewed definition exists.
    for schema_id, definition in catalog.items():
        if "x-peg-rex-validation-level" not in definition:
            upgraded.setdefault(schema_id, definition)
    upgraded.update(manual)
    for schema_id, definition in upgraded.items():
        filename = schema_id.removeprefix("pegrex.") + ".json"
        (root / "pegrex" / "jsonschemas" / filename).write_text(
            json.dumps(definition, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return {"registered": len(catalog), "upgraded": len(upgraded),
            "inferred_top_level": sum(v.get("x-peg-rex-validation-level") == "inferred-top-level" for v in upgraded.values()),
            "envelope_only": sum(str(v.get("x-peg-rex-validation-level", "")).startswith("envelope-only") for v in upgraded.values())}


if __name__ == "__main__":
    print(json.dumps(build(), indent=2, sort_keys=True))
