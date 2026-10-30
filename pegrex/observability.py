"""Runtime observations linked to static contracts without proof inflation."""
from __future__ import annotations
import hashlib, json, time
SCHEMA = "pegrex.observability-twin.v1"

def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

def ingest_trace(events, *, contract_index, source_revision, max_events=100_000):
    """Join trace events to known contract IDs; traces never prove unobserved paths."""
    if not isinstance(events, list) or len(events) > max_events:
        return {"schema": SCHEMA, "status": "unknown", "reason": "invalid-or-over-budget-trace"}
    known = contract_index if isinstance(contract_index, dict) else {}
    observed, unmatched = {}, []
    for i, event in enumerate(events):
        if not isinstance(event, dict):
            unmatched.append({"index": i, "reason": "malformed-event"}); continue
        cid = event.get("contract_id")
        if not isinstance(cid, str) or cid not in known:
            unmatched.append({"index": i, "reason": "contract-not-found"}); continue
        key = str(event.get("path_id", "unknown"))
        row = observed.setdefault(cid, {"observed_paths": set(), "count": 0, "contract_hash": _hash(known[cid])})
        row["observed_paths"].add(key); row["count"] += 1
    rows = {}
    for cid, contract in known.items():
        item = observed.get(cid, {"observed_paths": set(), "count": 0, "contract_hash": _hash(contract)})
        paths = sorted(item["observed_paths"])
        rows[cid] = {"observed_paths": paths, "event_count": item["count"],
                     "static_path_count": len(contract.get("paths", [])) if isinstance(contract, dict) else None,
                     "unobserved_static_paths": max(0, len(contract.get("paths", []))-len(paths)) if isinstance(contract, dict) else None,
                     "observation_is_proof": False, "contract_hash": item["contract_hash"]}
    return {"schema": SCHEMA, "status": "partial" if unmatched else "ok",
            "source_revision": source_revision, "trace_fingerprint": _hash(events),
            "contracts": rows, "unmatched_events": unmatched,
            "interpretation": "observed behavior is evidence of executions only; unobserved paths remain unresolved"}

def compare_trace_revisions(old, new):
    if old.get("source_revision") == new.get("source_revision"):
        return {"status": "comparable", "same_source_revision": True}
    return {"status": "unknown", "same_source_revision": False,
            "reason": "trace revisions differ; remap contracts before comparison"}
