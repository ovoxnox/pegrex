import pytest
import hashlib
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pegrex import evidence, zkproof
from pegrex.attest import canonical_json
from pegrex.zkproof import ZKProofError

SECRET = b"test-secret"
CTX = b"test domain"


def test_prove_verify_roundtrip():
    proof = zkproof.prove(SECRET, context=CTX)
    assert set(proof) == {"y", "t", "c", "s", "group"}
    assert proof["group"] == "rfc3526-1536"
    assert zkproof.verify(proof, context=CTX) is True
    binding = zkproof.generate_binding(SECRET)
    assert binding["y"] == proof["y"]
    # the proof never carries the exponent or the nonce
    assert "x" not in proof and "k" not in proof


def test_wrong_secret_y_swap_fails():
    attacker = dict(zkproof.prove(b"alice"))
    attacker["y"] = zkproof.generate_binding(b"bob")["y"]
    assert zkproof.verify(attacker) is False


def test_wrong_context_fails():
    proof = zkproof.prove(SECRET, context=CTX)
    assert zkproof.verify(proof, context=b"other") is False


def test_tampered_field_never_verifies_true():
    proof = zkproof.prove(SECRET, context=CTX)
    flipped = hex(int(proof["t"], 16) ^ 1)
    assert zkproof.verify({**proof, "t": flipped}, context=CTX) is False


def test_malformed_proof_raises_naming_field():
    proof = zkproof.prove(SECRET, context=CTX)
    for bad, name in (({**proof, "s": "zz"}, "'s'"),
                      ({**proof, "c": "1.5"}, "'c'"),
                      ({**proof, "t": "-1"}, "'t'"),
                      ({"y": proof["y"]}, "'t'")):
        try:
            zkproof.verify(bad, context=CTX)
            raised = None
        except ZKProofError as e:
            raised = e
        assert raised is not None, f"malformed proof accepted: {bad}"
        assert name in str(raised), str(raised)


def test_out_of_range_field_refused():
    proof = zkproof.prove(SECRET, context=CTX)
    try:
        zkproof.verify({**proof, "y": hex(zkproof.P)}, context=CTX)
        raised = None
    except ZKProofError as e:
        raised = e
    assert raised is not None and "'y'" in str(raised)


def test_group_self_check_refuses_bogus_group():
    real = (zkproof.P, zkproof.Q, zkproof._checked)
    zkproof.P = 2 ** 255 - 19          # a genuine prime, but NOT the group
    zkproof.Q = (zkproof.P - 1) // 2   # consistent shape, wrong group
    try:
        try:
            zkproof.generate_binding(SECRET)
            raised = None
        except ZKProofError as e:
            raised = e
    finally:
        zkproof.P, zkproof.Q, zkproof._checked = real
    assert raised is not None and "self-check" in str(raised)
    # the real group still works afterwards
    assert zkproof.verify(zkproof.prove(SECRET, context=CTX), context=CTX)


def test_claims_honesty_manifest():
    c = zkproof.claims()
    joined = " | ".join(c["not_proven"])
    assert c["proven"] and "discrete-log" in c["proven"][0]
    assert "NOT a zk-SNARK" in joined
    assert "post-quantum" in joined


def test_bind_evidence_bundle_integrity_plus_proof(tmp_path):
    pytest.importorskip("xxhash", reason="evidence bundle fingerprinting requires optional evidence dependency")
    src = tmp_path / "absval.py"
    src.write_text("def absval(n):\n    if n >= 0:\n        return n\n"
                   "    return -n\n")
    bundle = evidence.pack(src, tmp_path / "bundle", "k")
    bound = zkproof.bind_evidence(bundle, SECRET, "k")
    assert bound["ok"] is True and bound["bundle"]["ok"] is True
    body = json.loads((bundle / "manifest.json").read_text())["manifest"]
    ctx = hashlib.sha256(canonical_json(body).encode()).digest()
    assert zkproof.verify(bound["proof"], context=ctx) is True
    assert zkproof.verify(bound["proof"], context=b"forged") is False
    # tampered bundle: no proof is minted over a lie
    raw = bytearray((bundle / "contracts.json").read_bytes())
    raw[0] ^= 0x01
    (bundle / "contracts.json").write_bytes(bytes(raw))
    refused = zkproof.bind_evidence(bundle, SECRET, "k")
    assert refused["ok"] is False and "tampered" in refused["reason"]
