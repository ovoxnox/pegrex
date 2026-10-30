"""Offline neural-codegen candidate generation and independent staging checks."""
from __future__ import annotations

import re
from pathlib import Path

from . import SCHEMA
from .common import (artifact_record, backend_identity, prepare_staging,
                     read_bytes, read_json, read_text, run_argv,
                     sha256_file, unknown_result, validate_argv)

BACKEND_SCHEMA = "pegrex.neural-codegen-backend.v1"
_INCOMPLETE = re.compile(r"\bTODO\b|\btodo!\s*\(|\bunimplemented!\s*\(", re.IGNORECASE)


def _failure(operation: str, unknowns: list[str], **extra) -> dict:
    return unknown_result("neural-codegen", operation, unknowns, **extra)


def generate_candidate(spec_path: str, staging: str, backend_argv: list[str], *,
                       timeout_ms: int = 30_000, memory_mb: int = 512,
                       sandbox: bool = True) -> dict:
    """Generate Rust into staging; isolated execution is the production default.

    ``sandbox=False`` is reserved for explicitly trusted local development and
    must not be used for repository-controlled backend executables.
    """
    operation = "generate"
    try:
        argv = validate_argv(backend_argv)
        if not isinstance(sandbox, bool):
            raise ValueError("sandbox must be a Boolean")
        root = prepare_staging(staging)
        source = Path(spec_path)
        staged_payload = read_bytes(source)
        staged_input = root / "input.sexp"
        if staged_input.is_symlink():
            raise ValueError("staging input must not be a symbolic link")
        staged_input.write_bytes(staged_payload)
        report_path = root / "backend-report.json"
        result = run_argv(argv + ["--input", "input.sexp", "--output-dir", ".",
                                  "--report", "backend-report.json"],
                          cwd=root, timeout_ms=timeout_ms, memory_mb=memory_mb,
                          sandbox=sandbox)
        if not report_path.is_file():
            return _failure(operation, result["unknowns"] or [
                "neural-codegen backend produced no structured report"], execution=result)
        report = read_json(report_path)
        if report.get("schema") != BACKEND_SCHEMA:
            return _failure(operation, ["unsupported neural-codegen backend report schema"],
                            execution=result, backend_report=report)
        if result["status"] != "completed" or report.get("status") != "generated":
            unknowns = list(result["unknowns"])
            if report.get("error"):
                unknowns.append(str(report["error"]))
            return _failure(operation, unknowns or ["neural-codegen candidate was rejected"],
                            execution=result, backend_report=report)
        generated = root / "generated.rs"
        if not generated.is_file() or generated.is_symlink():
            return _failure(operation, ["backend success report has no regular generated.rs"],
                            execution=result, backend_report=report)
        # Independently parse and hash artifacts rather than trusting backend claims.
        read_text(generated, encoding="utf-8")
        artifacts = [artifact_record(root, staged_input, "s-expression"),
                     artifact_record(root, generated, "rust-source"),
                     artifact_record(root, report_path, "backend-report")]
        unknowns = ["generated Rust is a candidate; compilation, implementation completeness, security, and user intent remain unverified"]
        return {"schema": SCHEMA, "schema_version": 1, "backend": "neural-codegen",
                "backend_identity": backend_identity("neural-codegen", executable=argv[0]),
                "operation": operation, "status": "generated", "verdict": "unknown",
                "candidate": True, "staged": True, "promotion_allowed": False,
                "source_sha256": sha256_file(staged_input),
                "endpoint_count": report.get("endpoints"), "artifacts": artifacts,
                "checks": [], "unknowns": unknowns, "assumptions": [],
                "execution": {"returncode": result["returncode"], "sandbox": sandbox,
                              "argv_only": True, "network": "not requested",
                              "trusted_backend_required": not sandbox}}
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        return _failure(operation, [f"{type(error).__name__}: {error}"])


def verify_candidate(candidate_root: str, *, check_argv: list[str] | None = None,
                     timeout_ms: int = 120_000, memory_mb: int = 1024) -> dict:
    """Independently inspect staged Rust; never promote stubs or unreviewed intent."""
    operation = "verify_candidate"
    try:
        root = prepare_staging(candidate_root)
        sources = sorted(path for path in root.rglob("*.rs")
                         if "target" not in path.relative_to(root).parts)
        if not sources:
            return _failure(operation, ["no staged Rust source was found"])
        if len(sources) > 128:
            return _failure(operation, ["Rust source count budget exhausted"])
        artifacts, incomplete, audits, unknowns = [], [], [], []
        from ..core import get_engine
        for source in sources:
            text = read_text(source, encoding="utf-8")
            relative = source.relative_to(root).as_posix()
            artifacts.append(artifact_record(root, source, "rust-source"))
            markers = [{"line": number, "text": line.strip()[:200]}
                       for number, line in enumerate(text.splitlines(), 1)
                       if _INCOMPLETE.search(line)]
            if markers:
                incomplete.append({"path": relative, "markers": markers})
                unknowns.append(f"{relative}: generated implementation stubs remain")
            audit = get_engine().audit(source, language="rust")
            audit_unknowns = [str(row) for row in audit.unknowns]
            unknowns.extend(f"{relative}:{row}" for row in audit_unknowns)
            finding_count = len(audit.data) if isinstance(audit.data, list) else 0
            if finding_count:
                unknowns.append(f"{relative}: {finding_count} security analyzer findings require disposition")
            audits.append({"path": relative, "status": audit.status.value,
                           "finding_count": finding_count, "unknowns": audit_unknowns})
        compilation = {"status": "unknown", "executed": False,
                       "unknowns": ["no independent compilation command supplied"]}
        unknowns.append("compilation evidence unavailable")
        if check_argv is not None:
            argv = validate_argv(check_argv)
            compilation = run_argv(argv, cwd=root, timeout_ms=timeout_ms,
                                   memory_mb=memory_mb, sandbox=True)
            unknowns = [row for row in unknowns if row != "compilation evidence unavailable"]
            unknowns.extend(compilation["unknowns"])
            if compilation["status"] != "completed":
                unknowns.append("independent compilation did not complete")
        # Intent and general behavior are deliberately outside this mechanical gate.
        unknowns.append("independent checks do not establish user intent or general behavioral correctness")
        return {"schema": SCHEMA, "schema_version": 1, "backend": "neural-codegen",
                "operation": operation, "status": "checked", "verdict": "unknown",
                "candidate": True, "staged": True, "promotion_allowed": False,
                "artifacts": artifacts, "incomplete": incomplete, "security_audits": audits,
                "compilation": compilation, "unknowns": sorted(set(unknowns)),
                "assumptions": ["human requirements review is still required"],
                "scope": "candidate mechanics only; not production approval"}
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        return _failure(operation, [f"{type(error).__name__}: {error}"])
