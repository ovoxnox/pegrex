"""Compositional contract protocol with explicit obligations and UNKNOWN propagation."""
from __future__ import annotations
import hashlib, json
SCHEMA = "pegrex.compositional-verification.v1"

def _hash(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()

def component_record(name, contract, *, implementation_hash, dependencies=(), obligations=()):
    if not name or not isinstance(contract, dict) or not implementation_hash:
        raise ValueError("component requires name, contract and implementation hash")
    return {"schema": SCHEMA, "name": name, "contract": contract,
            "contract_hash": _hash(contract), "implementation_hash": implementation_hash,
            "dependencies": sorted(set(dependencies)), "obligations": list(obligations)}

def verify_composition(components, *, checked_obligations=()):
    """Combine components only when dependency records and required obligations exist.

    This protocol validates evidence bookkeeping; it does not prove a contract
    from a hash alone. `checked_obligations` must be produced by a trusted checker.
    """
    checked = set(checked_obligations)
    by_name = {c.get("name"): c for c in components if isinstance(c, dict) and c.get("name")}
    errors, unresolved = [], []
    for c in components:
        if not isinstance(c, dict) or c.get("schema") != SCHEMA:
            errors.append("invalid-component-record"); continue
        if c.get("contract_hash") != _hash(c.get("contract")):
            errors.append(f"contract-hash-mismatch:{c.get('name')}")
        for dep in c.get("dependencies", []):
            if dep not in by_name: unresolved.append(f"missing-dependency:{c.get('name')}:{dep}")
        for obligation in c.get("obligations", []):
            if obligation not in checked: unresolved.append(f"unverified-obligation:{c.get('name')}:{obligation}")
    status = "invalid" if errors else ("unknown" if unresolved else "evidence-complete")
    return {"schema": SCHEMA, "status": status, "components": sorted(by_name),
            "errors": errors, "unresolved": sorted(set(unresolved)),
            "claim": "evidence composition only; semantic validity requires trusted obligation checkers"}
