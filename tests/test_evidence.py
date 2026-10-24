import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pegrex import evidence

KEY = "k"
SRC = ("# ensures: result >= 0\n"
       "def absval(n):\n    if n >= 0:\n        return n\n    return -n\n")


def _pack(tmp_path, src_text=SRC, witnesses=None):
    src = tmp_path / "absval.py"
    src.write_text(src_text)
    bundle = evidence.pack(src, tmp_path / "bundle", KEY,
                           witnesses=witnesses)
    return src, bundle


def test_pack_verify_replay_stable(tmp_path):
    src, bundle = _pack(tmp_path, witnesses={"note.txt": "seen"})
    assert (bundle / "manifest.json").exists()
    assert (bundle / "contracts.json").exists()
    mf = json.loads((bundle / "manifest.json").read_text())
    assert mf["manifest"]["engine"]["name"] == "pegrex"
    assert mf["manifest"]["witnesses"]["note.txt"]["xxh64"]
    assert mf["signature"]
    v = evidence.verify(bundle, KEY)
    assert v["ok"] is True and v["artifacts"] == 2
    r = evidence.replay(bundle, KEY)
    assert r == {"ok": True, "stable": True, "diff": []}


def test_tampered_contracts_named(tmp_path):
    _, bundle = _pack(tmp_path)
    raw = bytearray((bundle / "contracts.json").read_bytes())
    raw[5] ^= 0x01
    (bundle / "contracts.json").write_bytes(bytes(raw))
    v = evidence.verify(bundle, KEY)
    assert v["ok"] is False and v["reason"] == "tampered:contracts"
    r = evidence.replay(bundle, KEY)
    assert r["ok"] is False and "tampered" in r["reason"]


def test_tampered_witness_named(tmp_path):
    _, bundle = _pack(tmp_path, witnesses={"w.txt": "hello"})
    p = bundle / "witnesses" / "w.txt"
    p.write_bytes(b"H" + p.read_bytes()[1:])
    v = evidence.verify(bundle, KEY)
    assert v["ok"] is False and v["reason"] == "tampered:witness:w.txt"


def test_wrong_key_signature_mismatch(tmp_path):
    _, bundle = _pack(tmp_path)
    v = evidence.verify(bundle, "nope")
    assert v["ok"] is False and v["reason"] == "signature mismatch"
    r = evidence.replay(bundle, "nope")
    assert r["ok"] is False


def test_legitimate_edit_stable_false_ok_true(tmp_path):
    src, bundle = _pack(tmp_path)
    src.write_text(SRC.replace("return n\n", "return n + 1\n"))
    r = evidence.replay(bundle, KEY)
    assert r["ok"] is True and r["stable"] is False
    assert any(d["kind"] == "result" for d in r["diff"])
    # and verify() itself is NOT tripped by source drift
    assert evidence.verify(bundle, KEY)["ok"] is True


def test_path_count_change_reported(tmp_path):
    src, bundle = _pack(tmp_path)
    src.write_text("def absval(n):\n    if n >= 0:\n        return n\n"
                   "    if n < -5:\n        return -n\n    return 0\n")
    r = evidence.replay(bundle, KEY)
    assert r["ok"] is True and r["stable"] is False
    assert any(d["kind"] == "path-count" for d in r["diff"])
