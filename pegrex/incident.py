"""Operational incident replay into feasible contracts and staged patch evidence."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from .repomemory import RepositoryMemory
from .semantics import verify_patch
from .smt import auto_feasible

SCHEMA = "pegrex.incident-replay.v1"


def _patch_evidence(candidate, root):
    path = Path(candidate["path"])
    if not path.is_absolute():
        path = root / path
    original = path.read_text(encoding="utf-8")
    proposed = candidate["proposed_source"]
    handle, output = tempfile.mkstemp(suffix=path.suffix)
    with os.fdopen(handle, "w", encoding="utf-8") as stream:
        stream.write(proposed)
    try:
        proof = verify_patch(str(path), output)
    finally:
        os.unlink(output)
    verdict = ("proved" if proof.get("verified") is True else
               "refuted" if (proof.get("counterexample") or {}).get("confirmed") else "unknown")
    return {"id": candidate.get("id"), "path": str(path),
            "function": candidate.get("function"), "verdict": verdict,
            "proof": proof, "applied": False,
            "unknowns": [] if verdict != "unknown" else ["patch candidate equivalence was not proved"]}


def replay_incident(trace, root, *, patch_candidates=()) -> dict:
    """Link runtime events to feasible contracts without applying candidates."""
    root = Path(root).resolve()
    unknowns = []
    try:
        memory = RepositoryMemory(root)
        memory.refresh()
        events, likely_paths = [], []
        for index, event in enumerate(trace):
            matches = memory.query_api(event.get("function", ""))
            if event.get("file"):
                matches = [row for row in matches if row["path"] == event["file"]]
            event_row = {"index": index, "function": event.get("function"),
                         "matches": [], "unknowns": []}
            if not matches:
                event_row["unknowns"].append("runtime function has no indexed contract")
            for api in matches:
                for contract in api["contracts"]:
                    constraints = list(contract["constraints"]) + list(event.get("constraints") or [])
                    feasible = auto_feasible(constraints)
                    row = {"event": index, "function": api["function"], "path": api["path"],
                           "contract": contract, "feasibility": feasible,
                           "source_sha256": api["source_sha256"]}
                    if feasible is False:
                        row["match"] = "infeasible-with-trace"
                    else:
                        row["match"] = "feasible-with-trace" if feasible is True else "unknown-feasibility"
                        likely_paths.append(row)
                        if feasible is None:
                            event_row["unknowns"].append("contract feasibility is unknown")
                    event_row["matches"].append(row)
            unknowns.extend(event_row["unknowns"])
            events.append(event_row)
        patches = []
        for candidate in patch_candidates:
            try:
                patches.append(_patch_evidence(candidate, root))
            except Exception as error:
                patches.append({"id": candidate.get("id"), "verdict": "unknown",
                                "applied": False, "unknowns": [f"patch candidate failed: {error}"]})
        unknowns.extend(reason for row in patches for reason in row.get("unknowns", []))
        unknowns.extend(memory.limitations)
        unknowns.append("a production trace covers observed events only; unseen paths remain possible")
        return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown",
                "events": events, "likely_paths": likely_paths,
                "patch_candidates": patches, "applied": False,
                "unknowns": sorted(set(unknowns)),
                "repository_memory": memory.memory_identity}
    except Exception as error:
        return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown",
                "events": [], "likely_paths": [], "patch_candidates": [],
                "applied": False, "unknowns": [f"incident replay failed: {type(error).__name__}: {error}"]}
