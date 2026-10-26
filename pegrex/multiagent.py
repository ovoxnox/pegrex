"""Separated agent roles with typed evidence and proof-gated edit delivery.

Generation and checking are deliberately different callables.  The final edit
still passes through :mod:`pegrex.patchgate`; role evidence never authorizes a
write by itself.
"""
from __future__ import annotations

import hashlib
import tempfile
from pathlib import Path

from .agenttools import find_counterexample, verify_change
from .kernel import check_certificate
from .patchgate import _certificate, apply_patch_gated

SCHEMA = "pegrex.multi-agent-change.v1"
ROLE_SCHEMA = "pegrex.agent-role-evidence.v1"


def _role(role: str, verdict: str, data=None, unknowns=()) -> dict:
    return {"schema": ROLE_SCHEMA, "schema_version": 1, "role": role,
            "verdict": verdict, "data": data if data is not None else {},
            "unknowns": list(unknowns)}


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _default_independent_check(before: str, after: str) -> dict:
    """Reverify and let the minimal kernel independently check the certificate."""
    evidence = verify_change(before, after)
    verification = evidence["data"].get("verification")
    if not isinstance(verification, dict):
        return _role("independent-checking", "unknown",
                     {"verifier": evidence}, evidence["unknowns"] or ["verifier-evidence-missing"])
    certificate = _certificate(before, after, verification)
    kernel = check_certificate(certificate)
    verdict = "proved" if kernel["checked"] and certificate["verdict"] == "proved" else (
        "refuted" if certificate["verdict"] == "refuted" else "unknown")
    unknowns = [] if verdict == "proved" else [kernel["reason"]]
    return _role("independent-checking", verdict,
                 {"certificate": certificate, "kernel": kernel,
                  "checker": "minimal-certificate-kernel"}, unknowns)


def _checking_role(checker, before: str, after: str) -> dict:
    try:
        result = checker(before, after)
        if isinstance(result, dict) and result.get("schema") == ROLE_SCHEMA:
            if result.get("role") != "independent-checking":
                return _role("independent-checking", "unknown", {"evidence": result},
                             ["independent-check-role-mismatch"])
            return result
        if isinstance(result, dict):
            verdict = result.get("verdict", "unknown")
            if verdict not in {"proved", "refuted", "unknown"}:
                verdict = "unknown"
            return _role("independent-checking", verdict, {"evidence": result},
                         [] if verdict == "proved" else ["independent-check-not-proved"])
        return _role("independent-checking", "unknown", {"evidence": result},
                     ["invalid-independent-check-evidence"])
    except Exception as error:
        return _role("independent-checking", "unknown", {},
                     [f"independent-check-error:{error}"])


def run_multi_agent_change(target: str | Path, candidate_generator, patch_generator, *,
                           finding=None, independent_checker=None,
                           require_equivalent=True, profile=None, invariants=None,
                           test_command=None, project_root=None, audit_dir=None,
                           timeout_ms=30_000, actor="multi-agent") -> dict:
    """Generate, materialize, challenge, independently check, then gate a change.

    ``candidate_generator(original_source, finding)`` returns a candidate
    specification. ``patch_generator(original_source, candidate, finding)``
    returns complete replacement source. An optional independent checker receives
    ``(before_path, after_path)`` and returns a role envelope or a mapping with a
    three-valued ``verdict``. It may not be either generator callable.
    """
    target = Path(target).resolve()
    roles = []
    try:
        original = target.read_text(encoding="utf-8")
    except OSError as error:
        roles.append(_role("candidate-generation", "unknown", {},
                           [f"source-read-error:{error}"]))
        return {"schema": SCHEMA, "schema_version": 1, "status": "rejected",
                "applied": False, "verdict": "unknown", "roles": roles,
                "unknowns": roles[0]["unknowns"], "patch_gate": None}
    try:
        candidate = candidate_generator(original, finding)
        if candidate is None:
            raise ValueError("candidate-generator-returned-none")
        roles.append(_role("candidate-generation", "ok",
                           {"candidate": candidate, "source_sha256": _sha(original)}))
    except Exception as error:
        roles.append(_role("candidate-generation", "unknown", {},
                           [f"candidate-generation-error:{error}"]))
        return {"schema": SCHEMA, "schema_version": 1, "status": "rejected",
                "applied": False, "verdict": "unknown", "roles": roles,
                "unknowns": roles[-1]["unknowns"], "patch_gate": None}
    try:
        proposed = patch_generator(original, candidate, finding)
        if not isinstance(proposed, str):
            raise TypeError("patch-generator-must-return-complete-source")
        roles.append(_role("patch-generation", "ok",
                           {"before_sha256": _sha(original), "after_sha256": _sha(proposed),
                            "changed": proposed != original}))
    except Exception as error:
        roles.append(_role("patch-generation", "unknown", {},
                           [f"patch-generation-error:{error}"]))
        return {"schema": SCHEMA, "schema_version": 1, "status": "rejected",
                "applied": False, "verdict": "unknown", "roles": roles,
                "unknowns": roles[-1]["unknowns"], "patch_gate": None}

    with tempfile.TemporaryDirectory(prefix="pegrex-agents-") as workspace:
        before = Path(workspace) / "before.py"
        after = Path(workspace) / "after.py"
        before.write_text(original, encoding="utf-8")
        after.write_text(proposed, encoding="utf-8")
        counterexample = find_counterexample(str(before), str(after))
        roles.append(_role("counterexample-search", counterexample["verdict"],
                           counterexample["data"], counterexample["unknowns"]))
        if independent_checker is candidate_generator or independent_checker is patch_generator:
            checked = _role("independent-checking", "unknown", {},
                            ["checker-must-be-independent-of-generators"])
        elif independent_checker is None:
            try:
                checked = _default_independent_check(str(before), str(after))
            except Exception as error:
                checked = _role("independent-checking", "unknown", {},
                                [f"independent-check-error:{error}"])
        else:
            checked = _checking_role(independent_checker, str(before), str(after))
        roles.append(checked)

    independence_ok = "checker-must-be-independent-of-generators" not in checked["unknowns"]
    proof_ok = checked["verdict"] == "proved" if require_equivalent else independence_ok

    def role_recheck(_staged):
        """Implement role recheck with the module's explicit API and failure semantics."""
        return {"allowed": proof_ok, "role": "independent-checking",
                "verdict": checked["verdict"], "unknowns": checked["unknowns"]}

    gate = apply_patch_gated(target, proposed, require_equivalent=require_equivalent,
        profile=profile, invariants=invariants, test_command=test_command,
        project_root=project_root, audit_dir=audit_dir, timeout_ms=timeout_ms,
        actor=actor, candidate_check=role_recheck)
    confirmed = bool(roles[2]["data"].get("confirmed") is True)
    verdict = "refuted" if confirmed else checked["verdict"]
    unknowns = [row for role in roles for row in role["unknowns"]] + list(gate.get("unknowns", []))
    return {"schema": SCHEMA, "schema_version": 1,
            "status": "applied" if gate.get("applied") else "rejected",
            "applied": bool(gate.get("applied")), "approved": bool(gate.get("approved")),
            "verdict": verdict, "roles": roles, "unknowns": unknowns,
            "patch_gate": gate,
            "independence": {"checker": "minimal-certificate-kernel" if independent_checker is None
                             else getattr(independent_checker, "__qualname__", "custom"),
                             "separate_from_generators": independence_ok}}
