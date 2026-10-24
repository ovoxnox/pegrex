"slsa - SLSA-style attestations."

import hashlib
import os

from .attest import hmac_sign, hmac_verify


class SigstoreUnavailableError(RuntimeError):
    pass


def hash_materials(paths):
    out = {}
    for p in paths:
        with open(p, "rb") as f:
            out[p] = hashlib.sha256(f.read()).hexdigest()
    return out


def attest(builder, command, cert_bundle, material_paths, key):
    """Build + sign a provenance statement."""
    prov = {
        "_type": "https://slsa.dev/provenance/v1",
        "builder": {"id": builder},
        "command": command,
        "cert_bundle": cert_bundle,
        "materials": hash_materials(material_paths),
    }
    sig = hmac_sign(prov, key)
    return {"provenance": prov, "signature": sig,
            "cert_bundle": cert_bundle}


def verify(attestation, key):
    """Re-check material hashes and the signature. Refusal names why."""
    prov = attestation.get("provenance")
    sig = attestation.get("signature")
    if not prov or not sig:
        return {"ok": False, "reason": "incomplete attestation"}
    for path, digest in prov.get("materials", {}).items():
        if not os.path.exists(path):
            return {"ok": False, "reason": f"material missing: {path}"}
        with open(path, "rb") as f:
            actual = hashlib.sha256(f.read()).hexdigest()
        if actual != digest:
            return {"ok": False, "reason": f"material tampered: {path}"}
    if not hmac_verify(prov, key, sig):
        return {"ok": False, "reason": "signature mismatch"}
    return {"ok": True, "materials": len(prov["materials"]),
            "builder": prov["builder"]["id"]}


def publish_sigstore(attestation, token=None):
    if not token:
        raise SigstoreUnavailableError(
            "slsa: Sigstore/Rekor publish needs credentials and network -- "
            "refusing to pretend publication happened")
    raise SigstoreUnavailableError(
        "slsa: network unavailable in this environment; attestation stays "
        "local (signature remains verifiable offline)")


def slsa_level(attestation):
    if not attestation.get("signature"):
        return "L0 (unsigned)"
    return "L2-equivalent (signed build provenance; hermeticity not claimed)"
