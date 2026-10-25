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
from .. import languages


class CapabilityError(NotImplementedError):
    """An operation is not registered for the requested language."""


class CoreEngine:
    schema = "pegrex.core-engine.v1"

    def language(self, path: str | Path | None = None, explicit: str | None = None,
                 default: str | None = None) -> str:
        resolved = languages.detect_language(path or "", explicit, default=default)
        if resolved is None:
            raise ValueError(f"cannot resolve language from path={path!r}, explicit={explicit!r}")
        return resolved

    def capabilities(self, language: str | None = None) -> dict:
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
        spec = languages.get_language(language)
        if "parse" not in spec.capabilities:
            raise CapabilityError(f"parse unsupported for {spec.name}: {spec.notes}")
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
        document = SourceDocument(source, spec.name)
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
        spec = languages.get_language(language)
        if "contracts" not in spec.capabilities:
            raise CapabilityError(f"contracts unsupported for {spec.name}: {spec.notes}")
        from hashlib import sha256
        source_hash = sha256(source.encode("utf-8")).hexdigest()
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
        document = SourceDocument.from_path(path, language)
        return self.extract_contracts(document.text, document.language, path=document.path)

    def audit(self, path: str | Path, language: str | None = None) -> OperationResult:
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
        spec = languages.get_language(language)
        if "callgraph" not in spec.capabilities:
            raise CapabilityError(f"call graph unsupported for {spec.name}: {spec.notes}")
        from ..callgraph import build_call_graph
        graph = build_call_graph(source, spec.name)
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
        elif raw.get("counterexample"):
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
        # Structural protocol keeps the stable core independent of a concrete
        # parser AST class. Frontends may adapt Nodes without changing the wire schema.
        if (hasattr(node, "tag") and hasattr(node, "pos")
                and hasattr(node, "endpos") and hasattr(node, "children")):
            return {"tag": node.tag, "pos": node.pos, "endpos": node.endpos,
                    "children": [CoreEngine._node_dict(child) for child in node.children]}
        if isinstance(node, list):
            return [CoreEngine._node_dict(item) for item in node]
        return node

    @staticmethod
    def _node_count(node: Any) -> int:
        count = 0
        stack = [node]
        while stack:
            current = stack.pop()
            if (hasattr(current, "tag") and hasattr(current, "children")
                    and hasattr(current, "pos") and hasattr(current, "endpos")):
                count += 1
                stack.extend(current.children)
            elif isinstance(current, list):
                stack.extend(current)
        return count


_engine = CoreEngine()


def get_engine() -> CoreEngine:
    """Process-wide stateless engine; caches belong to dedicated services."""
    return _engine
