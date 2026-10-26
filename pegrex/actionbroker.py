"""Separated agent planning, exact-plan authorization, sandboxing, and evidence."""
from __future__ import annotations

import hashlib
import json
import tempfile
from pathlib import Path, PurePosixPath

from .harness import check_plan
from .pocsandbox import run_poc

PLAN_SCHEMA = "pegrex.agent-action-plan.v1"
AUTH_SCHEMA = "pegrex.agent-action-authorization.v1"
EVIDENCE_SCHEMA = "pegrex.agent-action-evidence.v1"
_ISSUED_AUTHORIZATIONS = set()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _identity(value):
    return hashlib.sha256(_canonical(value).encode()).hexdigest()


def create_action_plan(actions) -> dict:
    """Serialize intent only; this function performs no authorization or execution."""
    if not isinstance(actions, list) or not actions or any(not isinstance(row, dict) for row in actions):
        return {"schema": PLAN_SCHEMA, "status": "unknown", "actions": [],
                "unknowns": ["plan must be a nonempty list of structured actions"]}
    payload = {"schema": PLAN_SCHEMA, "schema_version": 1, "actions": actions}
    return dict(payload, plan_id=_identity(payload), status="planned",
                authorized=False, executed=False, unknowns=[])


def authorize_action_plan(plan, policy, *, workspace) -> dict:
    """Default-deny authorization bound to exact plan, policy, and workspace."""
    try:
        if plan.get("schema") != PLAN_SCHEMA or plan.get("status") != "planned":
            raise ValueError("valid planned action document required")
        identity_payload = {key: plan[key] for key in ("schema", "schema_version", "actions")}
        if _identity(identity_payload) != plan.get("plan_id"):
            raise ValueError("plan identity mismatch")
        workspace = str(Path(workspace).resolve())
        checked = check_plan(plan["actions"], policy, base_dir=workspace)
        allowed = checked["safe"] and len(plan["actions"]) > 0
        payload = {"schema": AUTH_SCHEMA, "schema_version": 1, "plan_id": plan["plan_id"],
                   "policy_sha256": _identity(policy), "workspace": workspace,
                   "allowed": allowed, "decisions": checked["verdicts"]}
        authorization_id = _identity(payload)
        if allowed:
            _ISSUED_AUTHORIZATIONS.add(authorization_id)
        return dict(payload, authorization_id=authorization_id,
                    status="authorized" if allowed else "refused",
                    verdict="proved" if allowed else "refuted", unknowns=[])
    except Exception as error:
        return {"schema": AUTH_SCHEMA, "status": "unknown", "allowed": False,
                "verdict": "unknown", "unknowns": [f"authorization failed: {error}"]}


def revoke_action_authorization(authorization) -> None:
    """Revoke a locally issued execution capability before it is used."""
    _ISSUED_AUTHORIZATIONS.discard(authorization.get("authorization_id"))


class ActionEvidenceRecorder:
    """Hash-chain actual action evidence; this is not a cryptographic signature."""
    def __init__(self):
        self.records = []
        self.previous = "0" * 64

    def append(self, record):
        """Implement append with the module's explicit API and failure semantics."""
        payload = {"previous_sha256": self.previous, "record": record}
        digest = _identity(payload)
        stored = dict(payload, record_sha256=digest)
        self.records.append(stored)
        self.previous = digest
        return stored

    def attestation(self):
        """Implement attestation with the module's explicit API and failure semantics."""
        return {"schema": "pegrex.action-evidence-attestation.v1", "algorithm": "sha256-chain",
                "head_sha256": self.previous, "records": len(self.records),
                "authenticated": False,
                "scope": "local recorder integrity evidence; not a signed execution attestation"}


def _safe_file(name):
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not name:
        raise ValueError("unsafe action file path")
    return path


def execute_action_plan(plan, authorization, *, workspace, files=None,
                        sandbox_runner=run_poc, timeout_ms=5000, memory_mb=256) -> dict:
    """Execute only the exact authorized plan in an ephemeral staged workspace."""
    recorder = ActionEvidenceRecorder()
    unknowns = []
    try:
        expected_plan = {key: plan[key] for key in ("schema", "schema_version", "actions")}
        if _identity(expected_plan) != plan.get("plan_id") or authorization.get("plan_id") != plan.get("plan_id"):
            raise ValueError("execution plan differs from authorized plan")
        auth_payload = {key: authorization[key] for key in ("schema", "schema_version", "plan_id",
                        "policy_sha256", "workspace", "allowed", "decisions")}
        if _identity(auth_payload) != authorization.get("authorization_id"):
            raise ValueError("authorization identity mismatch")
        if not authorization.get("allowed") or authorization.get("status") != "authorized":
            raise ValueError("plan is not authorized")
        if authorization.get("authorization_id") not in _ISSUED_AUTHORIZATIONS:
            raise ValueError("authorization was not issued by this policy engine or was revoked")
        if str(Path(workspace).resolve()) != authorization.get("workspace"):
            raise ValueError("execution workspace differs from authorized workspace")
        current_files = {}
        for name, content in (files or {}).items():
            _safe_file(name)
            current_files[name] = content
        actual = []
        with tempfile.TemporaryDirectory(prefix="pegrex-action-broker-") as directory:
            staged = Path(directory) / "workspace"; staged.mkdir()
            for name, content in current_files.items():
                target = staged / _safe_file(name); target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(content.encode() if isinstance(content, str) else bytes(content))
            for index, action in enumerate(plan["actions"]):
                tool = action.get("tool")
                record = {"index": index, "tool": tool, "status": "unknown"}
                if tool == "shell":
                    argv = list(action.get("argv") or [])
                    result = sandbox_runner(argv, files=current_files,
                                            timeout_ms=timeout_ms, memory_mb=memory_mb)
                    record.update(argv=argv, execution=result,
                                  network={"disabled": bool((result.get("sandbox") or {}).get("no_network")),
                                           "evidence": result.get("sandbox")},
                                  filesystem_effects="unknown")
                    if result.get("sandbox", {}).get("no_network") is not True:
                        unknowns.append(f"action {index}:network disablement not proved")
                    unknowns.append(f"action {index}:sandbox result does not enumerate filesystem mutations")
                    if not result.get("executed"):
                        record["status"] = "unknown"
                        recorder.append(record); actual.append(record)
                        break
                    record["status"] = "executed"
                elif tool in {"read", "write"}:
                    name = action.get("path", "")
                    relative = _safe_file(name)
                    target = staged / relative
                    if tool == "write":
                        content = action.get("content")
                        if not isinstance(content, str):
                            raise ValueError("write action requires text content")
                        target.parent.mkdir(parents=True, exist_ok=True)
                        target.write_text(content, encoding="utf-8")
                        current_files[name] = content
                        record.update(path=name, bytes=len(target.read_bytes()),
                                      after_sha256=hashlib.sha256(target.read_bytes()).hexdigest(),
                                      filesystem_action="write", network={"disabled": True})
                    else:
                        data = target.read_bytes()
                        record.update(path=name, bytes=len(data),
                                      content_sha256=hashlib.sha256(data).hexdigest(),
                                      filesystem_action="read", network={"disabled": True})
                    record["status"] = "executed"
                else:
                    raise ValueError(f"unsupported authorized tool: {tool}")
                recorder.append(record); actual.append(record)
        completed = len(actual) == len(plan["actions"]) and all(row["status"] == "executed" for row in actual)
        evidence = {"schema": EVIDENCE_SCHEMA, "schema_version": 1,
                    "plan_id": plan["plan_id"], "authorization_id": authorization["authorization_id"],
                    "actions": actual, "recorder": recorder.attestation(),
                    "hash_chain": recorder.records,
                    "status": "executed" if completed else "unknown",
                    "verdict": "unknown" if unknowns or not completed else "proved",
                    "unknowns": sorted(set(unknowns)),
                    "scope": "actual argv/direct filesystem/network evidence in ephemeral staging; no real-target mutation"}
        evidence["evidence_identity"] = _identity(evidence)
        return evidence
    except Exception as error:
        unknowns.append(f"broker execution failed: {type(error).__name__}: {error}")
        evidence = {"schema": EVIDENCE_SCHEMA, "schema_version": 1, "status": "unknown",
                    "verdict": "unknown", "executed": False, "actions": recorder.records,
                    "recorder": recorder.attestation(), "unknowns": unknowns}
        evidence["evidence_identity"] = _identity(evidence)
        return evidence


def verify_action_evidence(evidence) -> dict:
    """Recompute recorder chain and evidence identity without trusting its labels."""
    try:
        previous = "0" * 64
        for stored in evidence["hash_chain"]:
            if stored["previous_sha256"] != previous:
                raise ValueError("evidence chain predecessor mismatch")
            expected = _identity({"previous_sha256": previous, "record": stored["record"]})
            if expected != stored["record_sha256"]:
                return {"schema": EVIDENCE_SCHEMA, "verified": False, "verdict": "refuted",
                        "unknowns": ["evidence record hash mismatch"]}
            previous = expected
        payload = {key: value for key, value in evidence.items() if key != "evidence_identity"}
        if _identity(payload) != evidence.get("evidence_identity"):
            return {"schema": EVIDENCE_SCHEMA, "verified": False, "verdict": "refuted",
                    "unknowns": ["evidence identity mismatch"]}
        return {"schema": EVIDENCE_SCHEMA, "verified": True,
                "verdict": evidence.get("verdict", "unknown"),
                "authenticated": False, "unknowns": list(evidence.get("unknowns") or [])}
    except Exception as error:
        return {"schema": EVIDENCE_SCHEMA, "verified": False, "verdict": "unknown",
                "unknowns": [f"evidence verification failed: {error}"]}
