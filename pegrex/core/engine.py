"""Stable orchestration layer over PegRex's optional analysis features.

Adapters below are intentionally lazy. The core owns language/capability
selection, result status, and contract normalization; specialized analyzers
remain separate and can evolve without changing the public result model.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from .contracts import canonicalize
from .models import OperationResult, OperationStatus, PathContract, SourceDocument, Verdict
from .operations import all_operation_parameters, operation_fields, operation_parameters
from .. import languages
from ..limits import MAX_AST_NODES
from ..errorpolicy import disclosed_error_message
from ..jsonshape import validate_object
from ..requestlimits import validate_request, validate_operation_budgets


class CapabilityError(NotImplementedError):
    """An operation is not registered for the requested language."""


class CoreEngine:
    schema = "pegrex.core-engine.v1"
    api_version = "2.0"

    def operations(self) -> dict:
        """Describe stable operations and their enforced JSON argument schemas."""
        from .operations import OPERATION_SCHEMAS
        return {
            "schema": "pegrex.core-operations.v2",
            "api_version": self.api_version,
            "operations": {name: operation_fields(name) for name in OPERATION_SCHEMAS},
            "schemas": all_operation_parameters(),
            "error_policy": "validation and implementation failures become status=error and verdict=unknown",
            "state_policy": "optional alpha/demo/beta profiles constrain execution and never authorize promotion",
        }

    def execute(self, operation: str, arguments: dict | None = None, *,
                disclose_errors: bool = False, state: str | None = None) -> OperationResult:
        """Invoke a named operation through the non-throwing production boundary.

        Direct methods retain their historical exceptions. This adapter is intended
        for CLI, RPC, and agent callers that require structured failures.
        """
        arguments = {} if arguments is None else arguments
        if not isinstance(arguments, dict):
            metadata = {"api_version": self.api_version,
                        "error_type": "ValueError",
                        "error_disclosure": "full" if disclose_errors else "redacted"}
            if state is not None:
                metadata.update(state=state, state_policy_enforced=False)
            return OperationResult(
                str(operation), OperationStatus.ERROR, verdict=Verdict.UNKNOWN,
                unknowns=["operation arguments must be a JSON object"],
                metadata=metadata)
        # Avoid mutating a caller-owned arguments object when adding effective
        # state-specific limits below.
        arguments = dict(arguments)
        methods = {
            "parse": self.parse,
            "contracts": self.extract_contracts,
            "contracts_file": self.contracts_file,
            "audit": self.audit,
            "call_graph": self.call_graph,
            "verify_patch": self.verify_patch,
            "soundness": self.soundness,
        }
        state_policy_enforced = False
        try:
            if not isinstance(operation, str):
                raise TypeError("operation name must be a string")
            parameters = operation_parameters(operation)
            validate_operation_budgets(arguments)
            validate_request(arguments)
            validate_object(arguments, parameters)
            if state is not None:
                from ..states import apply_profile_limits
                mutating = operation in {"neural.generate", "pythoc.compile", "release.create"}
                arguments, _profile = apply_profile_limits(
                    state, operation, arguments, mutates_workspace=mutating)
                state_policy_enforced = True
            if operation == "capabilities":
                metadata = {"api_version": self.api_version}
                if state is not None:
                    metadata.update(state=state, state_policy_enforced=True)
                return OperationResult(
                    "capabilities", OperationStatus.OK,
                    data=self.capabilities(arguments.get("language")),
                    metadata=metadata)
            integration = self._integration_operation(operation)
            if integration is not None:
                module, function = integration
                from importlib import import_module
                value = getattr(import_module(f"pegrex.integrations.{module}"), function)(**arguments)
                if not isinstance(value, dict):
                    raise TypeError(f"integration {operation!r} returned a non-object result")
                raw_unknowns = value.get("unknowns") or []
                if not isinstance(raw_unknowns, list):
                    raise TypeError(f"integration {operation!r} returned malformed unknowns")
                unknowns = [str(row) for row in raw_unknowns]
                raw_verdict = value.get("verdict")
                verdict = Verdict(raw_verdict) if raw_verdict in {"proved", "refuted", "unknown"} else None
                raw_status = value.get("status")
                if raw_status in {"error", "exception"}:
                    status = OperationStatus.ERROR
                elif raw_status in {"unknown", "partial", "timeout", "unavailable", "failed", "rejected"}:
                    status = OperationStatus.PARTIAL
                else:
                    status = OperationStatus.PARTIAL if unknowns or verdict is Verdict.UNKNOWN else OperationStatus.OK
                if status is OperationStatus.ERROR and not unknowns:
                    unknowns.append("integration backend reported an error")
                return OperationResult(
                    operation, status, verdict=verdict, data=value, unknowns=unknowns,
                    assumptions=list(value.get("assumptions") or []),
                    metadata={"api_version": self.api_version,
                              "backend": value.get("backend"), "candidate": value.get("candidate", False),
                              **({"state": state, "state_policy_enforced": True} if state else {})})
            method = methods.get(operation)
            if method is None:
                raise ValueError(f"unknown core operation {operation!r}")
            result = method(**arguments)
            result.metadata.setdefault("api_version", self.api_version)
            if state is not None:
                result.metadata["state"] = state
                result.metadata["state_policy_enforced"] = True
            return result
        except Exception as error:
            message = disclosed_error_message(error, disclose=disclose_errors)
            metadata = {"api_version": self.api_version,
                        "error_type": type(error).__name__,
                        "error_disclosure": "full" if disclose_errors else "redacted"}
            if state is not None:
                metadata.update(state=state, state_policy_enforced=state_policy_enforced)
            return OperationResult(str(operation), OperationStatus.ERROR, verdict=Verdict.UNKNOWN,
                                   unknowns=[f"{type(error).__name__}: {message}"],
                                   metadata=metadata)

    @staticmethod
    def _integration_operation(operation: str) -> tuple[str, str] | None:
        """Resolve optional backends lazily, outside the minimal trusted kernel."""
        operations = {
            "neural.generate": ("neural_codegen", "generate_candidate"),
            "neural.verify_candidate": ("neural_codegen", "verify_candidate"),
            "ironkernel.run": ("ironkernel_backend", "run_expression"),
            "ironkernel.differential": ("ironkernel_backend", "differential"),
            "pythoc.compile": ("pythoc_backend", "compile_source"),
            "pythoc.analyze_ir": ("pythoc_backend", "analyze_ir"),
            "pythoc.differential": ("pythoc_backend", "differential_native"),
        }
        return operations.get(operation)

    def language(self, path: str | Path | None = None, explicit: str | None = None,
                 default: str | None = None) -> str:
        """Implement language with the module's explicit API and failure semantics."""
        resolved = languages.detect_language(path or "", explicit, default=default)
        if resolved is None:
            raise ValueError(f"cannot resolve language from path={path!r}, explicit={explicit!r}")
        return resolved

    def capabilities(self, language: str | None = None) -> dict:
        """Implement capabilities with the module's explicit API and failure semantics."""
        if language:
            return languages.language_capabilities(language)
        return {"schema": "pegrex.language-capabilities.v1",
                "languages": languages.capability_matrix()}

    def soundness(self, language: str | None = None) -> OperationResult:
        """Return canonical frontend metadata and the observable trust policy."""
        report = languages.soundness_report(language)
        return OperationResult("soundness", OperationStatus.OK, data=report,
                               metadata={"language": languages.normalize_language(language),
                                         "plugin_count": len(report["plugins"])})

    def parse(self, source: str, language: str, *, function_body: bool = False,
              entrypoint: str | None = None) -> OperationResult:
        """Implement parse with the module's explicit API and failure semantics."""
        spec = languages.get_language(language)
        if "parse" not in spec.capabilities:
            raise CapabilityError(f"parse unsupported for {spec.name}: {spec.notes}")
        # Enforce the source byte budget before invoking any parser.
        document = SourceDocument(source, spec.name)
        if function_body:
            if "contracts" not in spec.capabilities or not spec.frontend_factory:
                raise CapabilityError(
                    f"function-body extraction unsupported for {spec.name}: {spec.notes}")
            frontend = languages.get_contract_frontend(spec.name)()
            parser = frontend[0]
            tree = parser(source, entrypoint) if entrypoint is not None else parser(source)
            if tree is None:
                raise ValueError(f"no function body found for {entrypoint or 'first function'} in {spec.name} source")
        else:
            tree = languages.parse_source(spec.name, source)
        return OperationResult("parse", OperationStatus.OK,
                               data={"language": spec.name, "tree": self._node_dict(tree),
                                     "node_count": self._node_count(tree)},
                               metadata={"parser": spec.parser,
                                         "parse_adapter": spec.parse_adapter,
                                         "mode": "function_body" if function_body else "module",
                                         "source_sha256": document.sha256,
                                         "source_characters": len(source),
                                         "source_utf8_bytes": len(source.encode("utf-8"))})

    def extract_contracts(self, source: str, language: str, *, path: str | None = None,
                          entrypoint: str | None = None) -> OperationResult:
        """Implement extract contracts with the module's explicit API and failure semantics."""
        spec = languages.get_language(language)
        if "contracts" not in spec.capabilities:
            raise CapabilityError(f"contracts unsupported for {spec.name}: {spec.notes}")
        document = SourceDocument(source, spec.name)
        source_hash = document.sha256
        pairs = languages.extract_contract_pairs(spec.name, source, entrypoint=entrypoint)
        typed = canonicalize(pairs)
        if not typed:
            return OperationResult(
                "contracts", OperationStatus.PARTIAL, data=[],
                unknowns=["no contract paths were extracted; this is not proof that the function has no behavior"],
                metadata={"language": spec.name, "source_sha256": source_hash,
                          "entrypoint": entrypoint})
        typed = [PathContract(row.constraints, row.outcome,
                              function=entrypoint or (Path(path).stem if path else None),
                              source_hash=source_hash) for row in typed]
        return OperationResult("contracts", OperationStatus.OK,
                               data=[row.to_dict() for row in typed],
                               metadata={"language": spec.name, "source_sha256": source_hash,
                                         "contract_count": len(typed),
                                         "contract_shape": "(constraints, outcome)",
                                         "entrypoint": entrypoint})

    def contracts_file(self, path: str | Path, language: str | None = None) -> OperationResult:
        """Implement contracts file with the module's explicit API and failure semantics."""
        document = SourceDocument.from_path(path, language)
        return self.extract_contracts(document.text, document.language, path=document.path)

    def audit(self, path: str | Path, language: str | None = None) -> OperationResult:
        """Implement audit with the module's explicit API and failure semantics."""
        resolved = self.language(path, language)
        if not languages.supports(resolved, "audit"):
            raise CapabilityError(f"audit unsupported for {resolved}")
        from tools.secaudit import audit as run_audit
        findings = run_audit(str(path), resolved)
        unknowns = [str(row.get("message", row.get("reason", "analysis incomplete")))
                    for row in findings if row.get("kind") in {"unknown", "analysis_unknown"}
                    or "UNKNOWN" in str(row.get("id", ""))]
        status = OperationStatus.PARTIAL if unknowns else OperationStatus.OK
        return OperationResult("audit", status, data=findings, unknowns=unknowns,
                               metadata={"language": resolved, "finding_count": len(findings)})

    def call_graph(self, source: str, language: str = "python") -> OperationResult:
        """Implement call graph with the module's explicit API and failure semantics."""
        spec = languages.get_language(language)
        if "callgraph" not in spec.capabilities:
            raise CapabilityError(f"call graph unsupported for {spec.name}: {spec.notes}")
        # Enforce the same input limit before parser and graph construction.
        document = SourceDocument(source, spec.name)
        from ..callgraph import build_call_graph
        graph = build_call_graph(document.text, spec.name)
        data = {"functions": sorted(graph.functions),
                "edges": [list(edge) for edge in sorted(graph.edges)],
                "dot": graph.to_dot(), "ascii": graph.to_ascii()}
        return OperationResult("call_graph", OperationStatus.OK, data=data,
                               metadata={"language": spec.name,
                                         "function_count": len(graph.functions),
                                         "edge_count": len(graph.edges)})

    def verify_patch(self, before_path: str | Path, after_path: str | Path,
                     claim: str = "equivalent") -> OperationResult:
        """Compare two source paths through the semantic-diff adapter.

        The underlying legacy API is path-based; argument names intentionally
        make that contract explicit instead of implying the strings are source text.
        """
        from ..semantics import verify_patch
        raw = verify_patch(str(before_path), str(after_path), claim)
        if raw.get("verified") is True:
            verdict = Verdict.PROVED
        elif (isinstance(raw.get("counterexample"), dict)
              and raw["counterexample"].get("confirmed") is True):
            verdict = Verdict.REFUTED
        else:
            verdict = Verdict.UNKNOWN
        status = OperationStatus.OK if verdict != Verdict.UNKNOWN else OperationStatus.PARTIAL
        unknowns = [raw.get("note", "analyzer could not decide")] if verdict == Verdict.UNKNOWN else []
        return OperationResult("verify_patch", status, data=raw, verdict=verdict,
                               unknowns=unknowns,
                               assumptions=list(raw.get("assumptions", [])),
                               metadata={"claim": claim, "before_path": str(before_path),
                                         "after_path": str(after_path)})

    @staticmethod
    def _node_dict(node: Any) -> Any:
        """Serialize normalized ASTs iteratively to avoid Python recursion limits."""
        def is_node(value: Any) -> bool:
            return (hasattr(value, "tag") and hasattr(value, "pos")
                    and hasattr(value, "endpos") and hasattr(value, "children"))

        built: dict[int, Any] = {}
        active: set[int] = set()
        stack = [(node, False)]
        node_count = 0
        while stack:
            current, visited = stack.pop()
            if is_node(current):
                key = id(current)
                if not visited:
                    if key in active:
                        raise ValueError("cyclic parse trees are not serializable")
                    active.add(key)
                    node_count += 1
                    if node_count > MAX_AST_NODES:
                        raise ValueError(f"parse tree exceeds {MAX_AST_NODES} node budget")
                    stack.append((current, True))
                    stack.extend((child, False)
                                 for child in reversed(current.children)
                                 if is_node(child) or isinstance(child, list))
                else:
                    active.discard(key)
                    children = [built[id(child)] if is_node(child) or isinstance(child, list)
                                else child for child in current.children]
                    built[key] = {"tag": current.tag, "pos": current.pos,
                                  "endpos": current.endpos, "children": children}
            elif isinstance(current, list):
                key = id(current)
                if not visited:
                    if key in active:
                        raise ValueError("cyclic parse trees are not serializable")
                    active.add(key)
                    stack.append((current, True))
                    stack.extend((child, False) for child in reversed(current)
                                 if is_node(child) or isinstance(child, list))
                else:
                    active.discard(key)
                    built[key] = [built[id(child)] if is_node(child) or isinstance(child, list)
                                  else child for child in current]
        if is_node(node) or isinstance(node, list):
            return built[id(node)]
        return node

    @staticmethod
    def _node_count(node: Any) -> int:
        """Count unique normalized nodes without looping on malformed cyclic input."""
        count = 0
        seen: set[int] = set()
        stack = [node]
        while stack:
            current = stack.pop()
            if id(current) in seen:
                continue
            seen.add(id(current))
            if (hasattr(current, "tag") and hasattr(current, "children")
                    and hasattr(current, "pos") and hasattr(current, "endpos")):
                count += 1
                if count > MAX_AST_NODES:
                    raise ValueError(f"parse tree exceeds {MAX_AST_NODES} node budget")
                stack.extend(current.children)
            elif isinstance(current, list):
                stack.extend(current)
        return count


_engine = CoreEngine()


def get_engine() -> CoreEngine:
    """Process-wide stateless engine; caches belong to dedicated services."""
    return _engine
