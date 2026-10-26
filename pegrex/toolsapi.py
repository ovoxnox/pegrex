"""Versioned, fail-closed Tools API for local, RPC, CLI, and agent callers.

The registry contains metadata only at rest; implementation imports are lazy.
Every invocation validates JSON-shaped arguments, confines declared paths to a
workspace, and returns a serializable evidence envelope. No tool in this API
executes shell commands or mutates its real workspace.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from typing import Any, Callable

from .core import OperationResult, OperationStatus, Verdict, get_engine

SCHEMA = "pegrex.tools-api-envelope.v2"
MANIFEST_SCHEMA = "pegrex.tools-api-manifest.v2"
API_VERSION = "2.0"


@dataclass(frozen=True)
class ToolSpec:
    """Public tool metadata and its lazy implementation adapter."""

    name: str
    summary: str
    parameters: dict[str, Any]
    handler: Callable[[dict[str, Any]], Any]
    path_arguments: tuple[str, ...] = ()
    trust_claim: bool = False

    def manifest(self) -> dict[str, Any]:
        """Implement manifest with the module's explicit API and failure semantics."""
        return {
            "name": self.name,
            "summary": self.summary,
            "parameters": self.parameters,
            "path_arguments": list(self.path_arguments),
            "trust_claim": self.trust_claim,
            "mutates_workspace": False,
        }


def _schema(properties, required=()):
    return {
        "type": "object",
        "properties": properties,
        "required": list(required),
        "additionalProperties": False,
    }


def _core_handler(operation):
    def call(arguments):
        """Implement call with the module's explicit API and failure semantics."""
        return get_engine().execute(operation, arguments)
    return call


def _lazy(module, function):
    def call(arguments):
        """Implement call with the module's explicit API and failure semantics."""
        from importlib import import_module
        return getattr(import_module(f"pegrex.{module}"), function)(**arguments)
    return call


def _registry():
    string = {"type": "string"}
    integer = {"type": "integer", "minimum": 0}
    boolean = {"type": "boolean"}
    mapping = {"type": "object"}
    array = {"type": "array"}
    specs = [
        ToolSpec("core.parse", "Parse source with a registered frontend.",
                 _schema({"source": string, "language": string,
                          "function_body": boolean, "entrypoint": string},
                         ["source", "language"]), _core_handler("parse")),
        ToolSpec("core.contracts", "Extract typed path contracts from source.",
                 _schema({"source": string, "language": string, "path": string,
                          "entrypoint": string}, ["source", "language"]),
                 _core_handler("contracts"), trust_claim=True),
        ToolSpec("core.contracts_file", "Extract typed path contracts from a workspace file.",
                 _schema({"path": string, "language": string}, ["path"]),
                 _core_handler("contracts_file"), ("path",), True),
        ToolSpec("core.audit", "Run the registered source security audit.",
                 _schema({"path": string, "language": string}, ["path"]),
                 _core_handler("audit"), ("path",)),
        ToolSpec("core.call_graph", "Build a source call graph.",
                 _schema({"source": string, "language": string}, ["source"]),
                 _core_handler("call_graph")),
        ToolSpec("core.verify_patch", "Check a semantic claim for two source files.",
                 _schema({"before_path": string, "after_path": string, "claim": string},
                         ["before_path", "after_path"]),
                 _core_handler("verify_patch"), ("before_path", "after_path"), True),
        ToolSpec("core.capabilities", "List registered language capabilities.",
                 _schema({"language": string}), _core_handler("capabilities")),
        ToolSpec("core.soundness", "Return frontend and trust-policy metadata.",
                 _schema({"language": string}), _core_handler("soundness")),
        ToolSpec("release.create", "Create proof-carrying repository release evidence.",
                 _schema({"root": string, "subjects": array, "builder_id": string,
                          "command_argv": array, "build_type": string,
                          "previous_root": string, "lockfile": string,
                          "materials": mapping, "internal_parameters": mapping},
                         ["root", "subjects", "builder_id", "command_argv", "build_type"]),
                 _lazy("releaseproof", "create_proof_carrying_release"),
                 ("root", "subjects", "previous_root", "lockfile", "materials"), True),
        ToolSpec("release.verify", "Independently verify release evidence and upstream artifacts.",
                 _schema({"pack": mapping, "root": string, "previous_root": string,
                          "lockfile": string, "subject_paths": array,
                          "material_paths": mapping}, ["pack", "root"]),
                 _lazy("releaseproof", "verify_release_pack"),
                 ("root", "previous_root", "lockfile", "subject_paths", "material_paths"), True),
        ToolSpec("assurance.invalidate", "Invalidate assurance claims from exact upstream hashes.",
                 _schema({"graph": mapping, "upstream_changes": mapping},
                         ["graph", "upstream_changes"]),
                 _lazy("assurancegraph", "invalidate_assurance"), trust_claim=True),
        ToolSpec("change_budget.summary", "Summarize semantic changes across two repository roots.",
                 _schema({"before_root": string, "after_root": string, "budget": mapping},
                         ["before_root", "after_root"]),
                 _lazy("changebudget", "summarize_semantic_change"),
                 ("before_root", "after_root"), True),
        ToolSpec("compliance_map.query", "Query an executable compliance map without legal inference.",
                 _schema({"graph": mapping, "classification": string, "kind": string,
                          "max_results": integer}, ["graph"]),
                 _lazy("compliancemap", "query_compliance_map")),
        ToolSpec("semantic_checksum.diff", "Diff normalized cross-language semantic checksums.",
                 _schema({"before_path": string, "after_path": string,
                          "type_assumptions": mapping, "domain_assumptions": mapping},
                         ["before_path", "after_path"]),
                 _lazy("semanticchecksum", "semantic_checksum_diff"),
                 ("before_path", "after_path"), True),
        ToolSpec("capsule.verify", "Verify a research capsule without executing its recipe.",
                 _schema({"path": string}, ["path"]),
                 _lazy("researchcapsule", "verify_research_capsule"), ("path",), True),
        ToolSpec("impact.simulate", "Simulate a patch only in an isolated staging copy.",
                 _schema({"root": string, "proposed_changes": mapping,
                          "boundaries": mapping, "api_specs": mapping},
                         ["root", "proposed_changes"]),
                 _lazy("impact", "simulate_change_impact"), ("root",)),
        ToolSpec("broker.verify", "Verify the local action-evidence hash chain.",
                 _schema({"evidence": mapping}, ["evidence"]),
                 _lazy("actionbroker", "verify_action_evidence"), trust_claim=True),
    ]
    return {spec.name: spec for spec in specs}


_REGISTRY = _registry()


def list_tools() -> dict[str, Any]:
    """Return the deterministic Tools API v2 manifest."""
    return {
        "schema": MANIFEST_SCHEMA,
        "api_version": API_VERSION,
        "tools": [_REGISTRY[name].manifest() for name in sorted(_REGISTRY)],
        "error_policy": "validation and implementation failures return status=error, verdict=unknown",
        "workspace_policy": "declared paths must resolve inside the caller-selected workspace",
    }


def _matches_type(value, expected):
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return True


def _validate(spec, arguments):
    if not isinstance(arguments, dict):
        raise ValueError("tool arguments must be a JSON object")
    schema = spec.parameters
    unknown = sorted(set(arguments) - set(schema["properties"]))
    if unknown:
        raise ValueError(f"unknown tool argument(s): {', '.join(unknown)}")
    missing = [name for name in schema["required"] if name not in arguments]
    if missing:
        raise ValueError(f"missing required tool argument(s): {', '.join(missing)}")
    for name, value in arguments.items():
        definition = schema["properties"][name]
        expected = definition.get("type")
        if expected and not _matches_type(value, expected):
            raise ValueError(f"argument {name!r} must be {expected}")
        if expected == "integer" and value < definition.get("minimum", value):
            raise ValueError(f"argument {name!r} is below its minimum")


def _resolve(workspace, value):
    path = Path(value)
    if not path.is_absolute():
        path = workspace / path
    resolved = path.resolve()
    try:
        resolved.relative_to(workspace)
    except ValueError as error:
        raise ValueError(f"path escapes tool workspace: {value!r}") from error
    return str(resolved)


def _confine_paths(spec, arguments, workspace):
    resolved = dict(arguments)
    for name in spec.path_arguments:
        if name not in resolved:
            continue
        value = resolved[name]
        if isinstance(value, str):
            resolved[name] = _resolve(workspace, value)
        elif isinstance(value, list) and all(isinstance(row, str) for row in value):
            resolved[name] = [_resolve(workspace, row) for row in value]
        elif isinstance(value, dict) and all(isinstance(row, str) for row in value.values()):
            resolved[name] = {key: _resolve(workspace, row) for key, row in value.items()}
        else:
            raise ValueError(f"path argument {name!r} has an unsupported shape")
    return resolved


def _identity(path):
    candidate = Path(path)
    row = {"path": str(candidate), "kind": "directory" if candidate.is_dir() else "file"}
    if candidate.is_file():
        digest = hashlib.sha256()
        with candidate.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        row.update(sha256=digest.hexdigest(), bytes=candidate.stat().st_size)
    elif not candidate.exists():
        row.update(kind="missing", error="path does not exist")
    return row


def _provenance(arguments, workspace):
    paths = []
    for name, value in sorted(arguments.items()):
        values = []
        if isinstance(value, str) and name in {
                "path", "root", "before_path", "after_path", "before_root",
                "after_root", "previous_root", "lockfile"}:
            values = [value]
        elif name in {"subjects", "subject_paths"} and isinstance(value, list):
            values = value
        elif name in {"materials", "material_paths"} and isinstance(value, dict):
            values = list(value.values())
        paths.extend(_identity(row) for row in values if isinstance(row, str))
    return {"workspace": str(workspace), "paths": paths}


def _unknowns(value):
    if isinstance(value, OperationResult):
        return [str(row) for row in value.unknowns]
    if not isinstance(value, dict):
        return []
    rows = value.get("unknowns") or []
    summary = value.get("unknown_summary") or {}
    rows = list(rows) + list(summary.get("entries") or [])
    return [row if isinstance(row, str) else json.dumps(row, sort_keys=True, default=str)
            for row in rows]


def _verdict(value, unknowns):
    if isinstance(value, OperationResult):
        return value.verdict
    if not isinstance(value, dict):
        return Verdict.UNKNOWN if unknowns else None
    verdict = value.get("verdict")
    if verdict in {"proved", "refuted", "unknown"}:
        return Verdict(verdict)
    if value.get("verified") is True:
        return Verdict.PROVED
    counterexample = value.get("counterexample") or {}
    if isinstance(counterexample, dict) and counterexample.get("confirmed") is True:
        return Verdict.REFUTED
    if unknowns or value.get("status") == "unknown" or value.get("valid") is False:
        return Verdict.UNKNOWN if value.get("valid") is not False else Verdict.REFUTED
    return None


def _envelope(name, value, provenance):
    unknowns = _unknowns(value)
    verdict = _verdict(value, unknowns)
    if isinstance(value, OperationResult):
        status = value.status
        data = value.data
        assumptions = list(value.assumptions)
        metadata = dict(value.metadata)
    else:
        status = OperationStatus.PARTIAL if unknowns or verdict is Verdict.UNKNOWN else OperationStatus.OK
        data = value
        assumptions = list(value.get("assumptions") or []) if isinstance(value, dict) else []
        metadata = {}
    metadata.update(api_version=API_VERSION, tool_schema=SCHEMA)
    return {
        "schema": SCHEMA,
        "api_version": API_VERSION,
        "tool": name,
        "status": status.value,
        "verdict": verdict.value if isinstance(verdict, Verdict) else verdict,
        "data": data,
        "unknowns": unknowns,
        "assumptions": assumptions,
        "metadata": metadata,
        "provenance": provenance,
        "error": None,
    }


def _error(name, error, provenance):
    return {
        "schema": SCHEMA,
        "api_version": API_VERSION,
        "tool": name,
        "status": OperationStatus.ERROR.value,
        "verdict": Verdict.UNKNOWN.value,
        "data": None,
        "unknowns": [f"{type(error).__name__}: {error}"],
        "assumptions": [],
        "metadata": {"api_version": API_VERSION, "error_type": type(error).__name__},
        "provenance": provenance,
        "error": {"type": type(error).__name__, "message": str(error)},
    }


def invoke(name: str, arguments: dict[str, Any] | None = None, *,
           workspace: str | Path = ".") -> dict[str, Any]:
    """Validate and invoke one registered tool without throwing across the API boundary."""
    root = Path(workspace).resolve()
    provenance = {"workspace": str(root), "paths": []}
    spec = _REGISTRY.get(name)
    if spec is None:
        return _error(name, ValueError(f"unknown tool {name!r}"), provenance)
    try:
        supplied = {} if arguments is None else arguments
        _validate(spec, supplied)
        confined = _confine_paths(spec, supplied, root)
        provenance = _provenance(confined, root)
        value = spec.handler(confined)
        return _envelope(name, value, provenance)
    except Exception as error:
        return _error(name, error, provenance)
