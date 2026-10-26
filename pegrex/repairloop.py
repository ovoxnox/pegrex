"""Generate, re-analyze, compare, and only then apply repair candidates."""
from __future__ import annotations

import ast
import os
import tempfile
from collections import Counter
from pathlib import Path

from .patchgate import apply_patch_gated
from .pocsandbox import run_poc, sandbox_status
from .policygate import SecurityProfile, evaluate_security_policy

SCHEMA = "pegrex.repair-recheck.v1"
AGENT_REPAIR_SCHEMA = "pegrex.agent-repair-differential.v1"


def _default_analyzer(path):
    from tools.secaudit import audit_report
    return audit_report(path)


def _identities(report):
    return Counter((row.get("id"), row.get("function"))
                   for row in report.get("findings", [])
                   if row.get("kind") != "unknown" and not row.get("suppressed"))


def repair_and_recheck(target: str | Path, finding: dict, generator, *,
                       analyzer=None, max_rounds=3, profile=None, invariants=None,
                       test_command=None, project_root=None, audit_dir=None,
                       timeout_ms=30_000, candidate_validator=None) -> dict:
    """A candidate is accepted only if the same analyzer confirms improvement.

    ``generator(current_source, finding, feedback)`` returns complete replacement
    source or None. Candidate analysis runs in the staged workspace before the
    target is touched. Every proposal, including rejected ones, is audited.
    """
    analyzer = analyzer or _default_analyzer
    profile = profile or SecurityProfile(require_proved=False)
    target = Path(target).resolve()
    original = target.read_text(encoding="utf-8")
    trail = []
    try:
        baseline = analyzer(str(target))
    except Exception as error:
        return {"schema": SCHEMA, "status": "unknown", "applied": False,
                "unknowns": [f"baseline-analysis-failed:{error}"], "trail": []}
    baseline_policy = evaluate_security_policy(baseline, profile)
    if not baseline_policy["allowed"]:
        return {"schema": SCHEMA, "status": "policy-refused", "applied": False,
                "baseline": baseline, "policy": baseline_policy, "trail": []}
    rule_id = finding.get("id")
    if not rule_id:
        return {"schema": SCHEMA, "status": "unknown", "applied": False,
                "unknowns": ["finding-without-stable-id"], "trail": []}
    baseline_counts = _identities(baseline)
    matching = sum(count for (identifier, _), count in baseline_counts.items() if identifier == rule_id)
    if not matching:
        return {"schema": SCHEMA, "status": "finding-not-present", "applied": False,
                "baseline": baseline, "trail": []}
    feedback = None
    for round_number in range(1, max_rounds + 1):
        current = target.read_text(encoding="utf-8")
        try:
            proposal = generator(current, finding, feedback)
        except Exception as error:
            trail.append({"round": round_number, "status": "generator-error", "error": str(error)})
            feedback = trail[-1]
            continue
        if proposal is None:
            trail.append({"round": round_number, "status": "no-candidate"})
            break
        try:
            if not isinstance(proposal, str):
                raise TypeError("repair candidate must be complete source text")
            ast.parse(proposal)
        except (SyntaxError, TypeError, ValueError) as error:
            trail.append({"round": round_number, "status": "invalid-candidate", "error": str(error)})
            feedback = trail[-1]
            continue

        def recheck(staged):
            """Implement recheck with the module's explicit API and failure semantics."""
            report = analyzer(staged)
            policy = evaluate_security_policy(report, profile)
            counts = _identities(report)
            remaining = sum(count for (identifier, _), count in counts.items() if identifier == rule_id)
            increased = [{"id": identifier, "function": function,
                          "before": baseline_counts[(identifier, function)], "after": count}
                         for (identifier, function), count in sorted(counts.items(), key=str)
                         if count > baseline_counts[(identifier, function)]]
            resolved = remaining < matching
            allowed = resolved and not increased and policy["allowed"]
            additional = None
            if candidate_validator is not None:
                try:
                    additional = candidate_validator(staged)
                    if not isinstance(additional, dict) or "allowed" not in additional:
                        additional = {"allowed": False,
                                      "unknowns": ["invalid-additional-candidate-validation"]}
                except Exception as error:
                    additional = {"allowed": False,
                                  "unknowns": [f"additional-candidate-validation-error:{error}"]}
                allowed = allowed and additional["allowed"] is True
            return {"allowed": allowed, "finding_resolved": resolved,
                    "remaining_matching_findings": remaining,
                    "new_or_increased_findings": increased,
                    "policy": policy, "before": baseline, "after": report,
                    "additional_validation": additional}

        gate = apply_patch_gated(target, proposal, profile=profile,
            require_equivalent=False, invariants=invariants, test_command=test_command,
            project_root=project_root, audit_dir=audit_dir, timeout_ms=timeout_ms,
            actor="repair-and-recheck", candidate_check=recheck)
        row = {"round": round_number, "status": "accepted" if gate["applied"] else "rejected",
               "gate": gate, "candidate_sha256": gate.get("after_sha256")}
        trail.append(row)
        if gate["applied"]:
            return {"schema": SCHEMA, "status": "repaired", "applied": True,
                    "rounds": round_number, "trail": trail, "patch": proposal,
                    "before": baseline, "after": gate["candidate_check"]["after"],
                    "audit_attempt_id": gate["audit_attempt_id"], "unknowns": []}
        feedback = {"gate": gate, "candidate_check": gate.get("candidate_check")}
    return {"schema": SCHEMA, "status": "unresolved", "applied": False,
            "rounds": len(trail), "trail": trail,
            "unchanged": target.read_text(encoding="utf-8") == original,
            "unknowns": ["no-repair-satisfied-recheck-and-policy"]}


def sandboxed_differential(before_path, after_path, *, argv, files=None,
                           target_name=None, timeout_ms=5000, memory_mb=256) -> dict:
    """Compare bounded observations of two source versions in separate sandboxes.

    Matching output is a passed differential test, never an equivalence proof.
    The caller supplies an argv-only harness and any auxiliary declared files.
    """
    schema = "pegrex.sandboxed-differential.v1"
    if isinstance(argv, str) or not argv or any(not isinstance(row, str) for row in argv):
        return {"schema": schema, "status": "unknown", "verdict": "unknown",
                "allowed": False, "unknowns": ["differential harness requires argv"]}
    target_name = target_name or Path(before_path).name
    relative = Path(target_name)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        return {"schema": schema, "status": "unknown", "verdict": "unknown",
                "allowed": False, "unknowns": ["unsafe differential target path"]}
    declared = dict(files or {})
    if target_name in declared:
        return {"schema": schema, "status": "unknown", "verdict": "unknown",
                "allowed": False, "unknowns": ["differential target collides with declared files"]}
    try:
        before_source = Path(before_path).read_bytes()
        after_source = Path(after_path).read_bytes()
    except OSError as error:
        return {"schema": schema, "status": "unknown", "verdict": "unknown",
                "allowed": False, "unknowns": [str(error)]}
    before_files = declared | {target_name: before_source}
    after_files = declared | {target_name: after_source}
    before = run_poc(argv, files=before_files, timeout_ms=timeout_ms,
                     memory_mb=memory_mb)
    if not before.get("executed"):
        return {"schema": schema, "status": "unknown", "verdict": "unknown",
                "allowed": False, "before": before, "after": None,
                "unknowns": before.get("unknowns") or ["before execution unavailable"]}
    after = run_poc(argv, files=after_files, timeout_ms=timeout_ms,
                    memory_mb=memory_mb)
    if not after.get("executed"):
        return {"schema": schema, "status": "unknown", "verdict": "unknown",
                "allowed": False, "before": before, "after": after,
                "unknowns": after.get("unknowns") or ["after execution unavailable"]}
    observations_match = (before.get("returncode") == after.get("returncode") and
                          before.get("evidence", "") == after.get("evidence", "") and
                          before.get("status") != "unknown" and after.get("status") != "unknown")
    if not observations_match:
        return {"schema": schema, "status": "different", "verdict": "refuted",
                "allowed": False, "observations_match": False,
                "before": before, "after": after,
                "unknowns": [], "counterexample": {
                    "confirmed": True, "kind": "sandboxed-differential",
                    "before_returncode": before.get("returncode"),
                    "after_returncode": after.get("returncode")}}
    return {"schema": schema, "status": "passed", "verdict": "unknown",
            "allowed": True, "observations_match": True,
            "before": before, "after": after,
            "unknowns": ["bounded differential observations do not prove semantic equivalence"]}


def _independent_validation(checker, before, after) -> dict:
    try:
        evidence = checker(str(before), str(after))
    except Exception as error:
        return {"allowed": False, "verdict": "unknown", "evidence": None,
                "unknowns": [f"independent-validation-error:{error}"]}
    if isinstance(evidence, bool):
        verdict = "proved" if evidence else "unknown"
        allowed = evidence
        unknowns = [] if evidence else ["independent checker did not prove validity"]
    elif isinstance(evidence, dict):
        verdict = evidence.get("verdict", "unknown")
        if verdict not in {"proved", "refuted", "unknown"}:
            verdict = "unknown"
        allowed = verdict == "proved" and evidence.get("allowed", True) is True
        unknowns = list(evidence.get("unknowns") or [])
        if not allowed and not unknowns:
            unknowns = ["independent checker did not prove validity"]
    else:
        verdict, allowed = "unknown", False
        unknowns = ["invalid independent checker result"]
    return {"allowed": allowed, "verdict": verdict, "evidence": evidence,
            "unknowns": unknowns}


def repair_with_sandboxed_differential(
        target: str | Path, finding: dict, generator, *, argv, independent_checker,
        files=None, target_name=None, analyzer=None, max_rounds=3, profile=None,
        invariants=None, test_command=None, project_root=None, audit_dir=None,
        timeout_ms=30_000, sandbox_timeout_ms=5000, memory_mb=256) -> dict:
    """Repair only with staged differential evidence and independent post-fix checks.

    The original source is restored if post-fix validation is not proved. All
    candidate attempts remain in the ordinary repair trail and edit audit.
    """
    target = Path(target).resolve()
    root = Path(project_root).resolve() if project_root else target.parent
    if not callable(independent_checker) or independent_checker is generator:
        return {"schema": AGENT_REPAIR_SCHEMA, "status": "unknown", "applied": False,
                "unchanged": True, "unknowns": ["independent checker required"]}
    available = sandbox_status()
    if not available.get("available"):
        return {"schema": AGENT_REPAIR_SCHEMA, "status": "unknown", "applied": False,
                "unchanged": True, "sandbox": available,
                "unknowns": available.get("unknowns") or ["sandbox unavailable"]}
    original = target.read_text(encoding="utf-8")
    with tempfile.TemporaryDirectory(prefix="pegrex-agent-repair-") as directory:
        before = Path(directory) / (target_name or target.name)
        before.parent.mkdir(parents=True, exist_ok=True)
        before.write_text(original, encoding="utf-8")

        def validate_candidate(staged):
            """Implement validate candidate with the module's explicit API and failure semantics."""
            differential = sandboxed_differential(
                before, staged, argv=argv, files=files, target_name=target_name,
                timeout_ms=sandbox_timeout_ms, memory_mb=memory_mb)
            independent = _independent_validation(independent_checker, before, staged)
            return {"allowed": differential["allowed"] and independent["allowed"],
                    "differential": differential, "independent": independent,
                    "unknowns": differential.get("unknowns", []) + independent.get("unknowns", [])}

        result = repair_and_recheck(
            target, finding, generator, analyzer=analyzer, max_rounds=max_rounds,
            profile=profile, invariants=invariants, test_command=test_command,
            project_root=root, audit_dir=audit_dir, timeout_ms=timeout_ms,
            candidate_validator=validate_candidate)
        response = dict(result, schema=AGENT_REPAIR_SCHEMA, repair_schema=SCHEMA,
                        sandbox=available)
        if not result.get("applied"):
            response["unchanged"] = target.read_text(encoding="utf-8") == original
            return response

        post_fix = _independent_validation(independent_checker, before, target)
        exact_candidate = target.read_text(encoding="utf-8") == result.get("patch")
        response["post_fix_validation"] = post_fix
        response["exact_candidate_applied"] = exact_candidate
        if post_fix["allowed"] and exact_candidate:
            response["trail"].append({"status": "post-fix-validation-proved",
                                      "independent": post_fix})
            response["post_fix_status"] = "proved"
            return response

        temporary = target.with_name(target.name + ".pegrex.rollback.tmp")
        temporary.write_text(original, encoding="utf-8")
        shutil_mode = target.stat().st_mode
        temporary.chmod(shutil_mode)
        os.replace(temporary, target)
        response["trail"].append({"status": "post-fix-validation-not-proved",
                                  "independent": post_fix})
        response.update(status="unknown", applied=False, rolled_back=True,
                        post_fix_status=post_fix["verdict"],
                        unchanged=target.read_text(encoding="utf-8") == original,
                        unknowns=list(response.get("unknowns") or []) +
                                 ["independent post-fix validation was not proved; original restored"])
        return response
