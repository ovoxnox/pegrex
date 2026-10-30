"""Canonical CoreEngine operation schemas shared with the Tools API.

The lists returned by ``CoreEngine.operations()`` remain compatible with the
existing v2 wire contract. The nested schemas are additive metadata and are
also enforced before dispatch so invalid calls fail before analyzer/backend
execution.
"""
from __future__ import annotations

from copy import deepcopy
from typing import Any


def _schema(properties: dict[str, Any], required=()) -> dict[str, Any]:
    return {"type": "object", "properties": properties,
            "required": list(required), "additionalProperties": False}


_STRING = {"type": "string"}
_INTEGER = {"type": "integer", "minimum": 0}
_BOOLEAN = {"type": "boolean"}
_MAPPING = {"type": "object"}
_ARRAY = {"type": "array", "maxItems": 4096}
_STRING_ARRAY = {"type": "array", "items": {"type": "string", "minLength": 1},
                 "maxItems": 128}
_BUDGETS = {"timeout_ms": {"type": "integer", "minimum": 1, "maximum": 300_000},
            "memory_mb": {"type": "integer", "minimum": 16, "maximum": 4096}}

OPERATION_SCHEMAS: dict[str, dict[str, Any]] = {
    "parse": _schema({"source": _STRING, "language": _STRING,
                      "function_body": _BOOLEAN, "entrypoint": _STRING},
                     ["source", "language"]),
    "contracts": _schema({"source": _STRING, "language": _STRING, "path": _STRING,
                          "entrypoint": _STRING}, ["source", "language"]),
    "contracts_file": _schema({"path": _STRING, "language": _STRING}, ["path"]),
    "audit": _schema({"path": _STRING, "language": _STRING}, ["path"]),
    "call_graph": _schema({"source": _STRING, "language": _STRING}, ["source"]),
    "verify_patch": _schema({"before_path": _STRING, "after_path": _STRING,
                             "claim": _STRING}, ["before_path", "after_path"]),
    "capabilities": _schema({"language": _STRING}),
    "soundness": _schema({"language": _STRING}),
    "neural.generate": _schema({"spec_path": _STRING, "staging": _STRING,
                                "backend_argv": _STRING_ARRAY, **_BUDGETS},
                               ["spec_path", "staging", "backend_argv"]),
    "neural.verify_candidate": _schema({"candidate_root": _STRING,
                                        "check_argv": _STRING_ARRAY, **_BUDGETS},
                                       ["candidate_root"]),
    "ironkernel.run": _schema({"expression": _MAPPING, "inputs": _MAPPING,
                               "max_elements": {"type": "integer", "minimum": 1,
                                                "maximum": 100_000}, **_BUDGETS},
                              ["expression", "inputs"]),
    "ironkernel.differential": _schema({
        "expression": _MAPPING, "inputs": _MAPPING,
        "max_elements": {"type": "integer", "minimum": 1, "maximum": 100_000},
        "atol": {"type": "number", "minimum": 0},
        "rtol": {"type": "number", "minimum": 0}, **_BUDGETS},
        ["expression", "inputs"]),
    "pythoc.compile": _schema({"source_path": _STRING, "staging": _STRING,
                               "entrypoint": _STRING, **_BUDGETS, "analyze": _BOOLEAN},
                              ["source_path", "staging", "entrypoint"]),
    "pythoc.analyze_ir": _schema({"ir_path": _STRING, "llvm_version": _STRING},
                                 ["ir_path", "llvm_version"]),
    "pythoc.differential": _schema({"before_path": _STRING, "after_path": _STRING,
                                    "argv": _STRING_ARRAY, "files": _MAPPING,
                                    "target_name": _STRING, **_BUDGETS},
                                   ["before_path", "after_path", "argv"]),
}

OPERATION_SUMMARIES = {
    "parse": "Parse source with a registered frontend.",
    "contracts": "Extract typed path contracts from source.",
    "contracts_file": "Extract typed path contracts from a workspace file.",
    "audit": "Run the registered source security audit.",
    "call_graph": "Build a source call graph.",
    "verify_patch": "Check a semantic claim for two source files.",
    "capabilities": "List registered language capabilities.",
    "soundness": "Return frontend and trust-policy metadata.",
    "neural.generate": "Generate a staged Rust candidate with offline neural-codegen.",
    "neural.verify_candidate": "Independently inspect staged Rust without promoting it.",
    "ironkernel.run": "Execute a bounded float64 expression in an isolated worker.",
    "ironkernel.differential": "Compare bounded ironkernel and NumPy observations.",
    "pythoc.compile": "Compile PythoC in an ephemeral sandbox and retain LLVM IR.",
    "pythoc.analyze_ir": "Parse an explicit supported LLVM IR grammar.",
    "pythoc.differential": "Replay two native candidates in isolated sandboxes.",
}


def operation_parameters(name: str) -> dict[str, Any]:
    """Return an independent schema object for one registered core operation."""
    if name not in OPERATION_SCHEMAS:
        raise ValueError(f"unknown core operation {name!r}")
    return deepcopy(OPERATION_SCHEMAS[name])


def operation_fields(name: str) -> list[str]:
    """Return the legacy ordered required/optional field catalog for an operation."""
    schema = OPERATION_SCHEMAS[name]
    required = schema["required"]
    optional = [f"{key}?" for key in schema["properties"] if key not in required]
    return [*required, *optional]


def all_operation_parameters() -> dict[str, dict[str, Any]]:
    """Return a defensive copy of every canonical operation schema."""
    return deepcopy(OPERATION_SCHEMAS)
