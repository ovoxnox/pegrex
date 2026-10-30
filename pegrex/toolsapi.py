"""Versioned, fail-closed Tools API for local, RPC, CLI, and agent callers.

The registry contains metadata only at rest; implementation imports are lazy.
Every invocation validates JSON-shaped arguments, confines declared paths to a
workspace, and returns a serializable evidence envelope. No tool executes shell
commands. Only explicitly marked integration operations write, and only beneath
caller-declared staging roots confined to the selected workspace.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Callable

from .core import OperationResult, OperationStatus, Verdict, get_engine
from .core.operations import operation_parameters
from .jsonshape import matches_type as _matches_type
from .jsonshape import validate_value as _validate_schema_value
from .requestlimits import validate_request, validate_operation_budgets
from .errorpolicy import disclosed_error_message
from .workspace import confine_paths as _confine_paths, provenance as _provenance

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
    mutates_workspace: bool = False

    def manifest(self) -> dict[str, Any]:
        """Implement manifest with the module's explicit API and failure semantics."""
        return {
            "name": self.name,
            "summary": self.summary,
            "parameters": self.parameters,
            "path_arguments": list(self.path_arguments),
            "trust_claim": self.trust_claim,
            "mutates_workspace": self.mutates_workspace,
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
    mapping = {"type": "object"}
    string_array = {"type": "array", "items": {"type": "string", "minLength": 1},
                    "maxItems": 128}
    specs = [
        ToolSpec("core.parse", "Parse source with a registered frontend.",
                 operation_parameters("parse"), _core_handler("parse")),
        ToolSpec("core.contracts", "Extract typed path contracts from source.",
                 operation_parameters("contracts"),
                 _core_handler("contracts"), trust_claim=True),
        ToolSpec("core.contracts_file", "Extract typed path contracts from a workspace file.",
                 operation_parameters("contracts_file"),
                 _core_handler("contracts_file"), ("path",), True),
        ToolSpec("core.audit", "Run the registered source security audit.",
                 operation_parameters("audit"), _core_handler("audit"), ("path",)),
        ToolSpec("core.call_graph", "Build a source call graph.",
                 operation_parameters("call_graph"), _core_handler("call_graph")),
        ToolSpec("core.verify_patch", "Check a semantic claim for two source files.",
                 operation_parameters("verify_patch"),
                 _core_handler("verify_patch"), ("before_path", "after_path"), True),
        ToolSpec("core.capabilities", "List registered language capabilities.",
                 operation_parameters("capabilities"), _core_handler("capabilities")),
        ToolSpec("core.soundness", "Return frontend and trust-policy metadata.",
                 operation_parameters("soundness"), _core_handler("soundness")),
        ToolSpec("neural.generate", "Generate a staged Rust candidate with offline neural-codegen.",
                 operation_parameters("neural.generate"),
                 _core_handler("neural.generate"), ("spec_path", "staging"),
                 mutates_workspace=True),
        ToolSpec("neural.verify_candidate", "Independently inspect staged Rust without promoting it.",
                 operation_parameters("neural.verify_candidate"),
                 _core_handler("neural.verify_candidate"), ("candidate_root",), True),
        ToolSpec("ironkernel.run", "Execute a bounded float64 expression in an isolated worker.",
                 operation_parameters("ironkernel.run"), _core_handler("ironkernel.run")),
        ToolSpec("ironkernel.differential", "Compare bounded ironkernel and NumPy observations.",
                 operation_parameters("ironkernel.differential"),
                 _core_handler("ironkernel.differential"), trust_claim=True),
        ToolSpec("pythoc.compile", "Compile PythoC in an ephemeral sandbox and retain LLVM IR.",
                 operation_parameters("pythoc.compile"),
                 _core_handler("pythoc.compile"), ("source_path", "staging"),
                 mutates_workspace=True),
        ToolSpec("pythoc.analyze_ir", "Parse an explicit supported LLVM IR grammar.",
                 operation_parameters("pythoc.analyze_ir"),
                 _core_handler("pythoc.analyze_ir"), ("ir_path",), True),
        ToolSpec("pythoc.differential", "Replay two native candidates in isolated sandboxes.",
                 operation_parameters("pythoc.differential"),
                 _core_handler("pythoc.differential"), ("before_path", "after_path"), True),
        ToolSpec("release.create", "Create proof-carrying repository release evidence.",
                 _schema({"root": string, "subjects": string_array, "builder_id": string,
                          "command_argv": string_array, "build_type": string,
                          "previous_root": string, "lockfile": string,
                          "materials": mapping, "internal_parameters": mapping},
                         ["root", "subjects", "builder_id", "command_argv", "build_type"]),
                 _lazy("releaseproof", "create_proof_carrying_release"),
                 ("root", "subjects", "previous_root", "lockfile", "materials"), True),
        ToolSpec("release.verify", "Independently verify release evidence and upstream artifacts.",
                 _schema({"pack": mapping, "root": string, "previous_root": string,
                          "lockfile": string, "subject_paths": string_array,
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
        "state_profiles": ["alpha", "demo", "beta"],
        "state_policy": "profiles are opt-in; all generated code remains a candidate and no profile authorizes automatic promotion",
    }


def _validate(spec: ToolSpec, arguments: Any) -> None:
    if not isinstance(arguments, dict):
        raise ValueError("tool arguments must be a JSON object")
    validate_operation_budgets(arguments)
    validate_request(arguments)
    schema = spec.parameters
    properties = schema["properties"]
    unknown = sorted(set(arguments) - set(properties))
    if unknown and schema.get("additionalProperties") is False:
        raise ValueError(f"unknown tool argument(s): {', '.join(unknown)}")
    missing = [name for name in schema.get("required", []) if name not in arguments]
    if missing:
        raise ValueError(f"missing required tool argument(s): {', '.join(missing)}")
    for name, value in arguments.items():
        if name in properties:
            _validate_schema_value(name, value, properties[name])

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


def _normalize_status(value: Any, unknowns: list[str], verdict: Verdict | None) -> OperationStatus:
    """Map backend status to the stable API status without erasing failures."""
    if isinstance(value, OperationResult):
        return value.status
    raw = value.get("status") if isinstance(value, dict) else None
    if raw in {"error", "exception"}:
        return OperationStatus.ERROR
    if raw in {"unknown", "partial", "timeout", "unavailable", "failed", "rejected"}:
        return OperationStatus.PARTIAL
    if unknowns or verdict is Verdict.UNKNOWN:
        return OperationStatus.PARTIAL
    return OperationStatus.OK


def _envelope(name, value, provenance):
    unknowns = _unknowns(value)
    verdict = _verdict(value, unknowns)
    if isinstance(value, OperationResult):
        status = value.status
        data = value.data
        assumptions = list(value.assumptions)
        metadata = dict(value.metadata)
    else:
        status = _normalize_status(value, unknowns, verdict)
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


def _error(name, error, provenance, *, disclose_errors=False, state=None,
           state_policy_enforced=False):
    message = disclosed_error_message(error, disclose=disclose_errors)
    metadata = {"api_version": API_VERSION, "error_type": type(error).__name__,
                "error_disclosure": "full" if disclose_errors else "redacted"}
    if state is not None:
        metadata.update(state=state, state_policy_enforced=state_policy_enforced)
    return {
        "schema": SCHEMA,
        "api_version": API_VERSION,
        "tool": name,
        "status": OperationStatus.ERROR.value,
        "verdict": Verdict.UNKNOWN.value,
        "data": None,
        "unknowns": [f"{type(error).__name__}: {message}"],
        "assumptions": [],
        "metadata": metadata,
        "provenance": provenance,
        "error": {"type": type(error).__name__, "message": message},
    }


def invoke(name: str, arguments: dict[str, Any] | None = None, *,
           workspace: str | Path = ".", disclose_errors: bool = False,
           state: str | None = None) -> dict[str, Any]:
    """Validate and invoke one registered tool without throwing across the API boundary.

    ``state`` is opt-in for backwards compatibility. Once selected, the profile
    is enforced before the tool handler runs, not merely recorded as metadata.
    Error metadata distinguishes a selected profile from completed enforcement.
    """
    state_policy_enforced = False
    try:
        root = Path(workspace).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, TypeError, ValueError):
        root = Path.cwd().resolve()
        provenance = {"workspace": str(root), "paths": []}
        return _error(name if isinstance(name, str) else "<invalid-tool-name>",
                      ValueError("workspace must be an existing resolvable directory"),
                      provenance, disclose_errors=disclose_errors, state=state,
                      state_policy_enforced=False)
    provenance = {"workspace": str(root), "paths": []}
    if not root.is_dir():
        return _error(name if isinstance(name, str) else "<invalid-tool-name>",
                      ValueError("workspace must be an existing directory"),
                      provenance, disclose_errors=disclose_errors, state=state,
                      state_policy_enforced=False)
    if not isinstance(name, str):
        return _error("<invalid-tool-name>", ValueError("tool name must be a string"),
                      provenance, disclose_errors=disclose_errors, state=state,
                      state_policy_enforced=False)
    spec = _REGISTRY.get(name)
    if spec is None:
        return _error(name, ValueError(f"unknown tool {name!r}"), provenance,
                      disclose_errors=disclose_errors, state=state,
                      state_policy_enforced=False)
    try:
        supplied = {} if arguments is None else arguments
        _validate(spec, supplied)
        if state is not None:
            from .states import apply_profile_limits
            supplied, _profile = apply_profile_limits(
                state, name, supplied, mutates_workspace=spec.mutates_workspace)
            state_policy_enforced = True
        confined = _confine_paths(spec, supplied, root)
        provenance = _provenance(confined, root)
        value = spec.handler(confined)
        envelope = _envelope(name, value, provenance)
        if state is not None:
            envelope["metadata"]["state"] = state
            envelope["metadata"]["state_policy_enforced"] = True
        return envelope
    except Exception as error:
        return _error(name, error, provenance, disclose_errors=disclose_errors,
                      state=state, state_policy_enforced=state_policy_enforced)
