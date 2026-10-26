"""Interprocedural function summaries with explicit evidence and coverage.

Local path contracts provide preconditions and return relations. Supported
single-argument return calls are composed bottom-up; direct and inherited
side effects remain separate evidence. Recursion, missing callees, and
unsupported compositions produce UNKNOWN composition coverage.
"""
from __future__ import annotations

import hashlib
import json

from .constraints import constraint_hash
from .effects import infer_effects, transitive_effects
from .incremental import IncrementalContractExtractor, _python_inventory
from .summaries import expand_calls

SCHEMA = "pegrex.interprocedural-summaries.v1"


def _identity(value: dict) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False, default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def summarize_source(source: str, *, path: str = "<memory>.py",
                     max_paths: int = 10_000, timeout_ms: int | None = None) -> dict:
    """Implement summarize source with the module's explicit API and failure semantics."""
    effect_report = infer_effects(source)
    inventory = _python_inventory(source)
    extractor = IncrementalContractExtractor(max_paths=max_paths, timeout_ms=timeout_ms)
    extraction = extractor.update(path, source)
    short_names: dict[str, list[str]] = {}
    for name in inventory:
        short_names.setdefault(name.rsplit(".", 1)[-1], []).append(name)

    calls: dict[str, list[str]] = {}
    external_calls: dict[str, list[str]] = {}
    recursive: set[str] = set()
    for name, metadata in inventory.items():
        internal: set[str] = set()
        external: set[str] = set()
        for dependency in metadata["dependencies"]:
            if dependency == name.rsplit(".", 1)[-1]:
                recursive.add(name)
                internal.add(name)
                continue
            matches = list(short_names.get(dependency, []))
            if matches:
                internal.update(matches)
            elif dependency in inventory:
                internal.add(dependency)
            else:
                external.add(dependency)
        calls[name] = sorted(internal)
        external_calls[name] = sorted(external)

    inherited = transitive_effects(effect_report["functions"], calls)
    local_contracts = {
        name: [(frozenset(row["constraints"]), row["outcome"])
               for row in extraction["summaries"][f"{path}::{name}"]["contracts"]]
        for name in inventory
    }
    parameters = {name: effect_report["functions"].get(name, {}).get("parameters", [])
                  for name in inventory}
    eligible = {name for name, value in local_contracts.items()
                if value and len(parameters[name]) == 1 and name not in recursive}
    eligible_contracts = {name: local_contracts[name] for name in eligible}
    eligible_params = {name: parameters[name][0] for name in eligible}

    functions: dict[str, dict] = {}
    for name, metadata in sorted(inventory.items()):
        local = extraction["summaries"][f"{path}::{name}"]
        preconditions = []
        postconditions = []
        return_relations = []
        for row in local["contracts"]:
            guards = row["constraints"]
            relation = "return is None" if row["outcome"] is None else f"return == {row['outcome']}"
            preconditions.append({"constraints": guards,
                                  "identity": row["constraint_identity"],
                                  "origin": "path"})
            postconditions.append({"constraints": guards, "relation": relation,
                                   "origin": "path-return"})
            return_relations.append(relation)
        unique_preconditions = list({row["identity"]: row for row in preconditions}.values())
        composition_unknowns: list[str] = []
        composed_pairs = local_contracts[name]
        if name in recursive:
            composition_unknowns.append("recursive return composition requires a fixpoint; local summary only")
        if local["status"] != "ok":
            composition_unknowns.extend(local["unknowns"])
        try:
            composed_pairs = expand_calls(local_contracts[name], eligible_contracts,
                                          eligible_params) if local_contracts[name] else []
        except Exception as exc:
            composition_unknowns.append(f"return composition unsupported: {type(exc).__name__}: {exc}")
        composed = [{"constraints": sorted(map(str, guards)),
                     "constraint_identity": constraint_hash(guards),
                     "relation": "return is None" if outcome is None else f"return == {outcome}"}
                    for guards, outcome in composed_pairs]
        effect_summary = inherited[name]
        if not effect_summary["complete"]:
            composition_unknowns.append("effect transitive closure incomplete at a cycle or missing callee")
        summary = {
            "schema": "pegrex.function-summary.v1",
            "function": name,
            "path": path,
            "parameters": parameters[name],
            "source_sha256": local["source_sha256"],
            "function_sha256": local["function_sha256"],
            "status": local["status"],
            "preconditions": unique_preconditions,
            "postconditions": postconditions,
            "return_relations": sorted(set(return_relations)),
            "side_effects": effect_summary["effects"],
            "effect_categories": effect_summary["categories"],
            "calls": calls[name],
            "external_calls": external_calls[name],
            "local_contracts": local["contracts"],
            "composed_postconditions": composed,
            "composition_status": "unknown" if composition_unknowns else "ok",
            "unknowns": sorted(set(composition_unknowns)),
        }
        summary["summary_identity"] = _identity(summary)
        functions[name] = summary

    report = {
        "schema": SCHEMA,
        "path": path,
        "language": "python",
        "source_sha256": effect_report["source_sha256"],
        "functions": functions,
        "status": "ok" if all(row["status"] == "ok" and
                              row["composition_status"] == "ok"
                              for row in functions.values()) else "unknown",
        "unknowns": sorted({unknown for row in functions.values()
                            for unknown in row["unknowns"]}),
    }
    report["summary_identity"] = _identity(report)
    return report
