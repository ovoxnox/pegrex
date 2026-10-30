"""Shareable, non-sensitive regression cases with content-addressed identities."""
from __future__ import annotations
import hashlib, json, re
from pathlib import Path
SCHEMA = "pegrex.regression-network.v1"
_SECRET = re.compile(r"(?i)(api[_-]?key|secret|password|token|private[_-]?key)\s*[:=]\s*['\"]?[\w./+=-]{8,}")
_PATH = re.compile(r"(?:(?:/home|/Users|/root|/tmp)/[^\s:'\"]+|[A-Za-z]:\\\\Users\\\\[^\s:'\"]+)")

def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def sanitize_case(case):
    """Reject likely secrets and machine-local paths instead of guessing redactions."""
    if not isinstance(case, dict) or not isinstance(case.get("pattern"), str) or not isinstance(case.get("test"), str):
        raise ValueError("case requires string pattern and test")
    raw = case["pattern"] + "\n" + case["test"]
    if _SECRET.search(raw): raise ValueError("possible-secret-in-case")
    if _PATH.search(raw): raise ValueError("machine-local-path-in-case")
    if len(raw.encode("utf-8")) > 128_000: raise ValueError("case-too-large")
    return {"schema": SCHEMA, "pattern": case["pattern"], "test": case["test"],
            "language": str(case.get("language", "unknown"))[:32],
            "rule_id": str(case.get("rule_id", "unknown"))[:128],
            "provenance": "user-reviewed-reproducible-case"}

def register_case(case, store):
    clean = sanitize_case(case)
    cid = hashlib.sha256(_canonical(clean)).hexdigest()
    path = Path(store); path.mkdir(parents=True, exist_ok=True)
    target = path / f"{cid}.json"
    payload = {**clean, "case_id": cid}
    if target.exists() and json.loads(target.read_text(encoding="utf-8")) != payload:
        raise RuntimeError("content-address-collision")
    target.write_bytes(_canonical(payload) + b"\n")
    return {"schema": SCHEMA, "status": "registered", "case_id": cid, "path": str(target)}

def minimize_case(case, predicate, *, max_attempts=128):
    """Greedy line/character deletion; predicate must reproduce the same finding."""
    clean = sanitize_case(case)
    attempts = 0
    for field in ("test", "pattern"):
        value = clean[field]
        changed = True
        while changed and attempts < max_attempts:
            changed = False
            for width in (max(1, len(value)//2), 1):
                for start in range(0, len(value), width):
                    attempts += 1
                    candidate = value[:start] + value[start+width:]
                    probe = dict(clean); probe[field] = candidate
                    if candidate and predicate(probe):
                        value, changed = candidate, True
                        break
                if changed or attempts >= max_attempts: break
        clean[field] = value
    clean["minimization"] = {"attempts": attempts, "predicate_confirmed": bool(predicate(clean))}
    return clean
