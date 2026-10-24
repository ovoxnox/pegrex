"""
attest — shared HMAC-SHA256 sign/verify primitives

Canonical-JSON body -> HMAC-SHA256 -> constant-time compare. Used by
marketplace.py (signed skill/rule-pack manifests) and slsa.py
(SLSA-style build provenance) -- both independently grew a
near-line-identical copy of this exact pattern; this is the one copy."""
from __future__ import annotations

import hashlib
import hmac
import json


def canonical_json(obj) -> str:
    """Deterministic JSON rendering: the same logical object always
    renders to the same bytes (sorted keys, no incidental whitespace),
    so signing and verification agree regardless of dict insertion order."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def hmac_sign(body, key: str) -> str:
    """HMAC-SHA256 hex digest over the canonical JSON rendering of `body`."""
    return hmac.new(key.encode(), canonical_json(body).encode(),
                    hashlib.sha256).hexdigest()


def hmac_verify(body, key: str, signature) -> bool:
    """Constant-time check that `signature` is the expected HMAC for `body`
    under `key`. A missing/empty signature is always rejected, never
    compared (there is nothing to compare against)."""
    if not signature:
        return False
    return hmac.compare_digest(hmac_sign(body, key), signature)
