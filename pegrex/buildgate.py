"""Policy-aware release gate: require evidence and pin trusted artifact identity."""
from __future__ import annotations
import hashlib, json
from pathlib import Path
SCHEMA = "pegrex.policy-build-gate.v1"

def sha256_file(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""): h.update(chunk)
    return h.hexdigest()

def evaluate_release(*, artifacts, required_evidence, evidence, trusted_hashes=None):
    """Return publishable only when required evidence is present and identities match."""
    trusted_hashes = trusted_hashes or {}
    missing = [name for name in required_evidence if not evidence.get(name)]
    artifact_rows, identity_changes = [], []
    for name, path in sorted(artifacts.items()):
        digest = sha256_file(path)
        expected = trusted_hashes.get(name)
        row = {"name": name, "sha256": digest, "trusted": expected is not None,
               "identity_matches": expected == digest if expected is not None else None}
        artifact_rows.append(row)
        if expected is not None and expected != digest: identity_changes.append(name)
    # Unpinned artifacts are explicitly not trusted; policy may require every artifact to be pinned.
    unpinned = [r["name"] for r in artifact_rows if not r["trusted"]]
    allowed = not missing and not identity_changes and not unpinned
    return {"schema": SCHEMA, "decision": "allow" if allowed else "deny",
            "publishable": allowed, "missing_evidence": missing,
            "identity_changes": identity_changes, "unpinned_artifacts": unpinned,
            "artifacts": artifact_rows}

def write_release_attestation(path, decision):
    Path(path).write_text(json.dumps(decision, sort_keys=True, indent=2)+"\n", encoding="utf-8")
