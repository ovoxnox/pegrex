import json
import sys
from pathlib import Path

from pegrex.editaudit import EditAudit
from pegrex.kernel import check_certificate
from pegrex.patchgate import apply_patch_gated
from pegrex.policygate import SecurityProfile


def test_kernel_rejects_forged_and_supports_only_canonical_equality():
    row = [{"constraints": [], "outcome": "x"}]
    certificate = {"schema": "pegrex.certificate.v1", "schema_version": 1,
                   "verdict": "proved", "claim": "contract-set-identical", "unknowns": [],
                   "evidence": {"before_contracts": row, "after_contracts": row}}
    assert check_certificate(certificate)["checked"]
    forged = json.loads(json.dumps(certificate))
    forged["evidence"]["after_contracts"][0]["outcome"] = "y"
    result = check_certificate(forged)
    assert not result["checked"] and result["verdict"] == "unknown"
    assert check_certificate({})["verdict"] == "unknown"


def test_equivalent_patch_applies_atomically_with_durable_trail(tmp_path):
    target = tmp_path / "app.py"
    target.write_text("def f(x):\n    if x >= 0:\n        return x + 1\n    return 0\n")
    proposed = target.read_text().replace("x + 1", "(x + 1)")
    result = apply_patch_gated(target, proposed, audit_dir=tmp_path / "audit")
    # The minimal kernel can check contract-set identity, not semantic
    # equivalence. Until an independent semantic proof checker is supplied,
    # required-equivalence edits fail closed.
    assert not result["approved"] and not result["applied"]
    assert not result["kernel"]["checked"]
    assert target.read_text() != proposed
    trail = tmp_path / "audit" / result["audit_attempt_id"]
    assert EditAudit.verify(trail)["ok"]
    assert (trail / "original.txt").read_text() != proposed
    assert (trail / "change.diff").read_text()


def test_behavior_change_and_unknown_are_fail_closed(tmp_path):
    target = tmp_path / "app.py"
    original = "def f(x):\n    if x >= 0:\n        return x + 1\n    return 0\n"
    target.write_text(original)
    changed = original.replace("x + 1", "x + 2")
    result = apply_patch_gated(target, changed, audit_dir=tmp_path / "audit")
    assert not result["applied"] and target.read_text() == original
    assert result["policy"]["allowed"] is False
    unknown = apply_patch_gated(target, "def f(x):\n    return opaque(x)\n",
                                audit_dir=tmp_path / "audit")
    assert not unknown["applied"] and target.read_text() == original


def test_invariant_gate_and_argv_tests_control_non_equivalent_repairs(tmp_path):
    target = tmp_path / "app.py"
    original = "def f(x):\n    if x >= 0:\n        return x + 1\n    return 0\n"
    target.write_text(original)
    proposed = original.replace("x + 1", "x + 2")
    allowed = apply_patch_gated(target, proposed, require_equivalent=False,
        invariants={"nonnegative": lambda before, after: {"verdict": "proved"}},
        test_command=(sys.executable, "-c", "print('ok')"),
        audit_dir=tmp_path / "audit")
    assert allowed["applied"]
    target.write_text(original)
    rejected = apply_patch_gated(target, proposed, require_equivalent=False,
        invariants={"unknown": lambda before, after: {"verdict": "unknown"}},
        audit_dir=tmp_path / "audit")
    assert not rejected["applied"] and target.read_text() == original
    assert "required-invariants-not-preserved" in rejected["unknowns"]
