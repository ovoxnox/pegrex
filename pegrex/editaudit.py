"""Durable evidence trail for every proposed automated edit."""
from __future__ import annotations

import difflib
import hashlib
import json
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "pegrex.edit-audit.v1"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _json(path: Path, value) -> None:
    _atomic(path, (json.dumps(value, sort_keys=True, indent=2, default=str) + "\n").encode())


class EditAudit:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def begin(self, target: str | Path, original: str, proposed: str,
              *, actor="automated", metadata=None) -> dict:
        """Implement begin with the module's explicit API and failure semantics."""
        attempt_id = uuid.uuid4().hex
        directory = self.root / attempt_id
        directory.mkdir(parents=True, exist_ok=False)
        patch = "".join(difflib.unified_diff(original.splitlines(True), proposed.splitlines(True),
                                             fromfile=str(target) + "@before",
                                             tofile=str(target) + "@after"))
        record = {"schema": SCHEMA, "attempt_id": attempt_id, "actor": actor,
                  "created_utc": datetime.now(timezone.utc).isoformat(),
                  "target": str(Path(target).resolve()), "status": "pending",
                  "original_sha256": _sha(original.encode()), "proposed_sha256": _sha(proposed.encode()),
                  "patch_sha256": _sha(patch.encode()), "metadata": metadata or {},
                  "artifacts": {"original": "original.txt", "proposed": "proposed.txt",
                                "patch": "change.diff"}}
        _atomic(directory / "original.txt", original.encode())
        _atomic(directory / "proposed.txt", proposed.encode())
        _atomic(directory / "change.diff", patch.encode())
        _json(directory / "attempt.json", record)
        return record

    def finish(self, attempt: dict, *, approved: bool, applied: bool, decision: dict,
               tests=None, proof_attempts=None) -> dict:
        """Implement finish with the module's explicit API and failure semantics."""
        directory = self.root / attempt["attempt_id"]
        final = dict(attempt, status="applied" if applied else ("rejected" if not approved else "approved-not-applied"),
                     completed_utc=datetime.now(timezone.utc).isoformat(),
                     approval={"approved": bool(approved), "applied": bool(applied),
                               "decision": decision},
                     tests=tests or [], proof_attempts=proof_attempts or [])
        if applied:
            final["applied_sha256"] = attempt["proposed_sha256"]
        _json(directory / "attempt.json", final)
        _json(directory / "decision.json", {"schema": "pegrex.edit-decision.v1",
                                            "attempt_id": attempt["attempt_id"],
                                            "approval": final["approval"],
                                            "tests": final["tests"],
                                            "proof_attempts": final["proof_attempts"]})
        return final

    @staticmethod
    def verify(attempt_dir: str | Path) -> dict:
        """Implement verify with the module's explicit API and failure semantics."""
        directory = Path(attempt_dir)
        try:
            record = json.loads((directory / "attempt.json").read_text(encoding="utf-8"))
            expected = {"original_sha256": "original.txt", "proposed_sha256": "proposed.txt",
                        "patch_sha256": "change.diff"}
            for key, name in expected.items():
                if _sha((directory / name).read_bytes()) != record[key]:
                    return {"ok": False, "reason": f"tampered:{name}"}
            return {"ok": True, "status": record["status"], "attempt_id": record["attempt_id"]}
        except (OSError, ValueError, KeyError) as error:
            return {"ok": False, "reason": str(error)}
