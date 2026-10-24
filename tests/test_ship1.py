try:
    import pytest
except ImportError:
    class _Raises:
        def __init__(self, exc): self.exc = exc
        def __enter__(self): return self
        def __exit__(self, t, v, tb):
            assert t is not None and issubclass(t, self.exc), f"expected {self.exc}"
            return True
    class _PytestShim:
        @staticmethod
        def raises(exc): return _Raises(exc)
    pytest = _PytestShim()


import os
import tempfile

from pegrex import bounty, harness, iac, tv, zk
from pegrex.modernize import modernize

C = chr(10)
COB = C.join(["       *> pegrex: result RES", "       PROCEDURE DIVISION.",
              "           IF N >= 0 THEN", "               MOVE N TO RES",
              "           ELSE", "               COMPUTE RES = 0 - N",
              "           END-IF.", "           GOBACK."])


def test_modernize_certified():
    p = os.path.join(tempfile.mkdtemp(), "a.cob")
    open(p, "w").write(COB)
    out = modernize(p)
    assert out["verified"] is True
    ns = {}
    exec(out["code"], ns)
    assert ns[[k for k in ns if not k.startswith("_")][0]](-7) == 7


def test_modernize_uncertified_target_no_claim():
    p = os.path.join(tempfile.mkdtemp(), "a.cob")
    open(p, "w").write(COB)
    out = modernize(p, target="rust")
    assert out["verified"] is None and "not certified" in out["note"]


def test_tv_wrap_discipline():
    assert tv.wrap({"verified": True})["verdict"] == tv.PROVED
    assert tv.wrap(None)["verdict"] == tv.UNKNOWN
    assert tv.wrap({"status": "refused"})["verdict"] == tv.REFUTED
    assert tv.check_never_claims_unknown_as_proved([None, {}, "x", {"verified": "maybe"}]) == []


def test_zk_underconstrained():
    bad = C.join(["template M() {", "    signal input a;",
                  "    signal output c;", "    c <-- a * b;", "}"])
    f = zk.audit_circuit(bad)["findings"]
    assert any(x["kind"] == "unconstrained-assignment" for x in f)


def test_iac_can():
    st = [{"Effect": "Allow", "Action": ["s3:Get*"],
           "Resource": ["arn:aws:s3:::b/*"]},
          {"Effect": "Deny", "Action": ["s3:*"],
           "Resource": ["arn:aws:s3:::b/secret/*"]}]
    assert iac.can(st, "s3:GetObject", "arn:aws:s3:::b/x") == "allow"
    assert iac.can(st, "s3:GetObject", "arn:aws:s3:::b/secret/k") == "deny"


def test_harness_default_deny():
    v = harness.check_action({"tool": "shell", "args": "rm -rf /"},
                             harness.default_policy())
    assert v["verdict"] == "refused"


def test_bounty_poc_and_unknown():
    src = C.join(["def f(x):", "    if x > 5 and x > 0:", "        db_execute(x)",
                  "    return 1"])
    out = bounty.run(src, "db_execute")
    assert out["status"] == "poc" and out["payload"]["x"] > 5
    assert bounty.run("def f(x):\n    return 1", "db_execute")["status"] == "unknown"
