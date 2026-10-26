"""Proof-gated, atomic patch application with independent certificate checks."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from .editaudit import EditAudit
from .kernel import check_certificate
from .policygate import SecurityProfile, evaluate_security_policy
from .schema import certificate_document

SCHEMA = "pegrex.patch-gate.v1"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def _canonical_contracts(path) -> list[dict]:
    from .semantics import contracts_of
    return [{"constraints": sorted(constraints), "outcome": outcome}
            for constraints, outcome in contracts_of(str(path))]


def _certificate(before, after, verification) -> dict:
    verdict = "proved" if verification.get("verified") is True else (
        "refuted" if verification.get("counterexample", {}).get("confirmed") else "unknown")
    evidence = {"before_contracts": _canonical_contracts(before),
                "after_contracts": _canonical_contracts(after)}
    from .kernel import contract_set_identity
    evidence["before_contracts_sha256"] = contract_set_identity(evidence["before_contracts"])
    evidence["after_contracts_sha256"] = contract_set_identity(evidence["after_contracts"])
    return certificate_document(verdict, "equivalent", evidence=evidence,
        unknowns=[] if verdict == "proved" else [verification.get("note", "equivalence-not-proved")],
        counterexample=verification.get("counterexample"),
        before_source_sha256=_sha(Path(before).read_text(encoding="utf-8")),
        after_source_sha256=_sha(Path(after).read_text(encoding="utf-8")))


def _invariants(invariants, before, after) -> tuple[list[dict], bool]:
    rows, preserved = [], True
    for name, checker in sorted((invariants or {}).items()):
        try:
            result = checker(str(before), str(after))
            if isinstance(result, bool):
                verdict = "proved" if result else "refuted"
                result = {"verdict": verdict}
            verdict = result.get("verdict", "proved" if result.get("preserved") is True else "unknown")
            if verdict not in {"proved", "refuted", "unknown"}:
                verdict = "unknown"
            rows.append({"name": name, "verdict": verdict, "evidence": result})
            preserved = preserved and verdict == "proved"
        except Exception as error:
            rows.append({"name": name, "verdict": "unknown", "error": str(error)})
            preserved = False
    return rows, preserved


def _run_tests(command, cwd, timeout_ms) -> dict:
    if isinstance(command, str):
        return {"argv": [], "status": "unknown", "reason": "raw-shell-test-command-refused"}
    try:
        result = subprocess.run(list(command), cwd=cwd, capture_output=True, text=True,
                                timeout=timeout_ms / 1000, shell=False)
        return {"argv": list(command), "returncode": result.returncode,
                "status": "passed" if result.returncode == 0 else "failed",
                "stdout": result.stdout[-4000:], "stderr": result.stderr[-4000:]}
    except subprocess.TimeoutExpired:
        return {"argv": list(command), "status": "unknown", "reason": "test-timeout"}
    except OSError as error:
        return {"argv": list(command), "status": "unknown", "reason": str(error)}


def apply_patch_gated(target: str | Path, proposed_source: str, *,
                      profile: SecurityProfile | None = None, invariants=None,
                      test_command=None, project_root: str | Path | None = None,
                      audit_dir: str | Path | None = None, require_equivalent=True,
                      timeout_ms=30_000, actor="automated", candidate_check=None) -> dict:
    """Implement apply patch gated with the module's explicit API and failure semantics."""
    target = Path(target).resolve()
    original = target.read_text(encoding="utf-8")
    profile = profile or SecurityProfile()
    root = Path(project_root).resolve() if project_root else target.parent
    relative = target.relative_to(root)
    audit = EditAudit(audit_dir or root / ".pegrex-audit")
    attempt = audit.begin(target, original, proposed_source, actor=actor,
                          metadata={"profile": profile.to_dict(),
                                    "require_equivalent": require_equivalent})
    tests, proofs, unknowns = [], [], []
    try:
        with tempfile.TemporaryDirectory() as workspace:
            staged_root = Path(workspace) / "repository"
            shutil.copytree(root, staged_root, ignore=shutil.ignore_patterns(
                ".git", "__pycache__", ".pegrex-audit", ".pytest_cache", "dist", "build"))
            staged = staged_root / relative
            staged.write_text(proposed_source, encoding="utf-8")
            verification = None
            certificate = None
            kernel = None
            if require_equivalent:
                from .semantics import verify_patch
                verification = verify_patch(str(target), str(staged))
                certificate = _certificate(target, staged, verification)
                kernel = check_certificate(certificate)
                proofs.append({"kind": "semantic-equivalence", "verification": verification,
                               "certificate": certificate, "kernel": kernel})
                policy_report = {"verdict": kernel["verdict"],
                                 "unknowns": [] if kernel["checked"] else [kernel["reason"]],
                                 "counterexample": verification.get("counterexample")}
            else:
                policy_report = {"unknowns": []}
            invariant_rows, invariants_preserved = _invariants(invariants, target, staged)
            proofs.extend({"kind": "invariant", **row} for row in invariant_rows)
            if test_command is not None:
                test = _run_tests(test_command, staged_root, timeout_ms)
                tests.append(test)
            tests_passed = all(row["status"] == "passed" for row in tests)
            candidate_result = None
            if candidate_check is not None:
                try:
                    candidate_result = candidate_check(str(staged))
                    if not isinstance(candidate_result, dict) or "allowed" not in candidate_result:
                        candidate_result = {"allowed": False, "reason": "invalid-candidate-check-result"}
                except Exception as error:
                    candidate_result = {"allowed": False, "reason": f"candidate-check-error:{error}"}
                proofs.append({"kind": "candidate-recheck", "result": candidate_result})
            decision = evaluate_security_policy(policy_report, profile)
            approved = decision["allowed"] and invariants_preserved and tests_passed
            if candidate_result is not None:
                approved = approved and candidate_result["allowed"] is True
            if require_equivalent:
                approved = approved and bool(kernel and kernel["checked"])
            if not invariants_preserved:
                unknowns.append("required-invariants-not-preserved")
            if test_command is not None and not tests_passed:
                unknowns.append("tests-not-passed")
            applied = False
            if approved:
                temporary = target.with_name(target.name + ".pegrex.tmp")
                temporary.write_text(proposed_source, encoding="utf-8")
                shutil.copymode(target, temporary)
                os.replace(temporary, target)
                applied = True
            response = {"schema": SCHEMA, "approved": approved, "applied": applied,
                        "policy": decision, "certificate": certificate, "kernel": kernel,
                        "invariants": invariant_rows, "tests": tests,
                        "candidate_check": candidate_result, "unknowns": unknowns,
                        "audit_attempt_id": attempt["attempt_id"],
                        "before_sha256": _sha(original), "after_sha256": _sha(proposed_source)}
            final = audit.finish(attempt, approved=approved, applied=applied,
                                 decision=decision | {"unknowns": unknowns},
                                 tests=tests, proof_attempts=proofs)
            response["audit"] = final
            return response
    except Exception as error:
        decision = {"allowed": False, "error": str(error)}
        audit.finish(attempt, approved=False, applied=False, decision=decision,
                     tests=tests, proof_attempts=proofs)
        return {"schema": SCHEMA, "approved": False, "applied": False,
                "unknowns": [f"patch-gate-error:{error}"],
                "audit_attempt_id": attempt["attempt_id"]}
