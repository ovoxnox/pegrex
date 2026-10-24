"""
marketplace — signed skill/rule packs 

║  Manifests are HMAC-SHA256 signed over the canonical JSON body. Install 
║  happens ONLY on a valid signature for the expected key: tampered       
║  rules, wrong keys, and unsigned manifests are refused. This turns the  
║  extension.py shape into a trust boundary."""

from __future__ import annotations

from .attest import canonical_json as canonical, hmac_sign, hmac_verify


def sign_manifest(manifest: dict, key: str) -> dict:
    """Attach an HMAC signature over the canonical body."""
    if not isinstance(manifest, dict) or "rules" not in manifest:
        raise ValueError("marketplace: manifest needs a 'rules' list")
    out = dict(manifest)
    out["signature"] = hmac_sign(manifest, key)
    return out


def verify_manifest(signed: dict, key: str) -> dict:
    """Independent re-verification. Refuses loudly with a reason."""
    if not isinstance(signed, dict):
        return {"ok": False, "reason": "not a manifest"}
    sig = signed.get("signature")
    if not sig:
        return {"ok": False, "reason": "unsigned manifest"}
    body = {k: v for k, v in signed.items() if k != "signature"}
    if "rules" not in body:
        return {"ok": False, "reason": "manifest has no rules"}
    if not hmac_verify(body, key, sig):
        return {"ok": False, "reason": "signature mismatch (tampered or wrong key)"}
    return {"ok": True, "rules": len(body["rules"]), "name": body.get("name")}


def install(signed: dict, key: str) -> dict:
    """Install ONLY a verified pack; otherwise refuse with the reason."""
    v = verify_manifest(signed, key)
    if not v["ok"]:
        return {"status": "refused", **v}
    return {"status": "installed", "name": v.get("name"),
            "rules": v["rules"], "verified": True}
