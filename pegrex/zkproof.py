"""
zkproof - zero-knowledge Sigma protocol bindings

Schnorr proofs of knowledge over the RFC 3526 1536-bit MODP group only --
the published constants below, never a hand-rolled group. At first use (and
again whenever the constants are monkeypatched) the group self-check runs:
g must lie in the prime-order-q subgroup of the safe prime p, i.e.
pow(g, q, p) == 1 with q = (p-1)/2. (The brief's literal "8*g == 1 mod p"
cannot hold for the published g=2 -- 8*2 mod p is 16 -- so the realized
check is the mathematically meaningful subgroup-membership equation; a group
failing it is refused, loudly, never run.)

Fiat-Shamir heuristic: the challenge is sha256 over fixed-length encodings
of g || t || y || context, so the transcript is bound to the commitment,
the public key, and the caller's context string.

Honesty (mirroring pegrex.zk.is_mock_check): this is a classical Sigma
protocol -- O(1) group elements, NOT a zk-SNARK; it proves knowledge of the
secret's binding preimage and nothing about source semantics; it is not
post-quantum. claims() says exactly that.
"""
from __future__ import annotations

import hashlib
import secrets

# RFC 3526, section 2 ("1536-bit MODP Group") -- published constants
# (cross-checked against scapy/twisted/paramiko copies of the same group).
_P_HEX = """
FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
670C354E 4ABC9804 F1746C08 CA237327 FFFFFFFF FFFFFFFF
"""
G = 2
P = int("".join(_P_HEX.split()), 16)
Q = (P - 1) // 2                     # prime order of g in the safe prime p
GROUP = "rfc3526-1536"
_P_BYTES = P.to_bytes(192, "big")    # fixed-length encodings for hashing


class ZKProofError(ValueError):
    pass


_checked = None                      # (P, Q, G) that passed the self-check


def _ensure_group():
    """Subgroup self-check, run once per distinct constant set. A bogus or
    monkeypatched group is refused -- this engine never rolls its own."""
    global _checked
    if _checked == (P, Q, G):
        return
    if P % 2 != 1 or not (2 <= G <= P - 2) or Q != (P - 1) // 2:
        raise ZKProofError(
            "zkproof: group constants inconsistent (need safe prime p, "
            "q = (p-1)/2, 2 <= g <= p-2) -- refusing to run")
    if pow(G, Q, P) != 1:
        raise ZKProofError(
            "zkproof: group self-check failed: g is not in the prime-order-q "
            "subgroup of the declared MODP group (pow(g, q, p) != 1) -- "
            "refusing to run on this group")
    _checked = (P, Q, G)


def _x(secret: bytes) -> int:
    if not isinstance(secret, (bytes, bytearray)):
        raise ZKProofError(
            f"zkproof: secret must be bytes, got {type(secret).__name__}")
    return int.from_bytes(hashlib.sha256(bytes(secret)).digest(),
                          "big") % (P - 1)


def _challenge(t: int, y: int, context: bytes) -> int:
    h = hashlib.sha256()
    h.update(_P_BYTES)                       # g, fixed length
    h.update(t.to_bytes(192, "big"))
    h.update(y.to_bytes(192, "big"))
    h.update(context)                        # caller-bound transcript domain
    return int.from_bytes(h.digest(), "big") % Q


def generate_binding(secret: bytes) -> dict:
    """y = g^x mod p with x = sha256(secret) mod (p-1). x is derived and
    immediately discarded -- it is never stored or revealed."""
    _ensure_group()
    y = pow(G, _x(secret), P)
    return {"y": f"{y:x}", "group": GROUP}


def prove(secret: bytes, context: bytes = b"") -> dict:
    """Schnorr proof of knowledge of the binding preimage.

    k random in [1, p-2]; t = g^k; c = H(g || t || y || context) mod q;
    s = (k + c*x) mod (p-1). The response carries NO x and NO k."""
    _ensure_group()
    x = _x(secret)
    y = pow(G, x, P)
    k = secrets.randbelow(P - 2) + 1
    t = pow(G, k, P)
    c = _challenge(t, y, context)
    s = (k + c * x) % (P - 1)
    return {"y": f"{y:x}", "t": f"{t:x}", "c": f"{c:x}", "s": f"{s:x}",
            "group": GROUP}


def _field(proof, name: str) -> int:
    v = proof.get(name)
    if not isinstance(v, str):
        raise ZKProofError(f"zkproof: proof field {name!r} missing or not a string")
    try:
        n = int(v, 16)
    except ValueError:
        raise ZKProofError(f"zkproof: proof field {name!r} is not hex")
    if n < 1 or n > P - 1:
        raise ZKProofError(f"zkproof: proof field {name!r} out of range")
    return n


def verify(proof, context: bytes = b"") -> bool:
    """Recompute c; check g^s == t * y^c (mod p). Malformed proofs raise
    ZKProofError naming the field; well-formed-but-wrong proofs return
    False -- never True by accident."""
    _ensure_group()
    if not isinstance(proof, dict):
        raise ZKProofError("zkproof: proof must be a mapping")
    y, t, c, s = (_field(proof, "y"), _field(proof, "t"),
                  _field(proof, "c"), _field(proof, "s"))
    if proof.get("group", GROUP) != GROUP:
        raise ZKProofError(
            f"zkproof: unsupported group {proof.get('group')!r}")
    if _challenge(t, y, context) != c:
        return False
    return pow(G, s, P) == (t * pow(y, c, P)) % P


def claims() -> dict:
    return {
        "proven": [
            "knowledge of the secret binding preimage (discrete-log "
            "knowledge, Fiat-Shamir heuristic)",
        ],
        "not_proven": [
            "source semantic correctness (use evidence.py replay for that)",
            "SNARK succinctness -- this is a Sigma protocol, O(1) group "
            "elements but NOT a zk-SNARK",
            "post-quantum security -- classical discrete log",
        ],
    }


def bind_evidence(bundle_dir, secret, key) -> dict:
    """Combine with pegrex.evidence: verify the bundle HMAC first, then
    attach a binding + proof whose Fiat-Shamir context is the bundle's
    signed manifest hash. A verifier checks bundle integrity and the proof
    without the source ever leaving the holder's hands."""
    _ensure_group()
    from . import evidence
    v = evidence.verify(bundle_dir, key)
    if not v["ok"]:
        return {"ok": False, "reason": v["reason"]}
    import json
    from .attest import canonical_json
    body = json.loads((evidence.pathlib.Path(bundle_dir) / "manifest.json")
                      .read_text())["manifest"]
    context = hashlib.sha256(canonical_json(body).encode()).digest()
    return {"ok": True, "bundle": v, "binding": generate_binding(secret),
            "proof": prove(secret, context=context)}
