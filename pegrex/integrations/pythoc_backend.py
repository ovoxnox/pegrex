"""PythoC native compilation, versioned LLVM analysis, and isolated differentials."""
from __future__ import annotations

from pathlib import Path
import shutil
import sys

from . import SCHEMA
from .common import (artifact_record, prepare_staging, read_bytes, read_json,
                     read_text, run_argv, sha256_file, unknown_result)
from ..compilerir import parse_compiler_ir

_SUPPORTED_IR = {".ll"}


def _failure(operation: str, unknowns: list[str], **extra) -> dict:
    return unknown_result("pythoc", operation, unknowns, **extra)


def _llvm_major(value) -> str | None:
    if isinstance(value, list) and value:
        return str(value[0])
    if isinstance(value, str) and value.split(".", 1)[0].isdigit():
        return value.split(".", 1)[0]
    return None


def analyze_ir(ir_path: str, llvm_version: str | int) -> dict:
    """Parse only a supported explicit LLVM grammar; no semantic-equivalence claim."""
    try:
        path = Path(ir_path)
        if path.is_symlink():
            raise ValueError("LLVM artifact must not be a symbolic link")
        path = path.absolute()
        if path.suffix not in _SUPPORTED_IR:
            raise ValueError("LLVM analysis requires a .ll artifact")
        text = read_text(path, encoding="utf-8")
        report = parse_compiler_ir(text, format="llvm", version=str(llvm_version), proof_mode=True)
        unknowns = list(report.get("unknowns") or [])
        return {"schema": SCHEMA, "schema_version": 1, "backend": "pythoc",
                "operation": "analyze_ir", "status": report.get("status", "unknown"),
                "verdict": report["verdict"], "candidate": True,
                "artifacts": [artifact_record(path.parent, path, "llvm-ir")],
                "ir_analysis": report, "unknowns": unknowns,
                "assumptions": ["the supplied LLVM grammar version exactly matches the artifact"],
                "scope": "parsed control-flow structure only; not memory safety or semantic equivalence"}
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        return _failure("analyze_ir", [f"{type(error).__name__}: {error}"])


def compile_source(source_path: str, staging: str, entrypoint: str, *,
                   timeout_ms: int = 120_000, memory_mb: int = 1024,
                   analyze: bool = True) -> dict:
    """Compile in an ephemeral OS sandbox and retain independently hashed LLVM IR."""
    operation = "compile"
    try:
        if not isinstance(entrypoint, str) or not entrypoint.isidentifier():
            raise ValueError("PythoC entrypoint must be an identifier")
        root = prepare_staging(staging)
        source = root / "candidate.py"
        source.write_bytes(read_bytes(source_path))
        worker = root / "pythoc_worker.py"
        shutil.copyfile(Path(__file__).with_name("_pythoc_worker.py"), worker)
        ir_path, report_path = root / "candidate.ll", root / "backend-report.json"
        result = run_argv([sys.executable, "pythoc_worker.py", "candidate.py",
                           "candidate.ll", "backend-report.json", entrypoint],
                          cwd=root, timeout_ms=timeout_ms, memory_mb=memory_mb, sandbox=True)
        if not report_path.is_file():
            return _failure(operation, result["unknowns"] or [
                "PythoC worker produced no report; optional dependency or sandbox may be unavailable"],
                execution=result)
        report = read_json(report_path)
        if report.get("schema") != "pegrex.pythoc-worker.v1":
            return _failure(operation, ["unsupported PythoC worker report schema"], execution=result)
        if result["status"] != "completed" or report.get("status") != "compiled":
            return _failure(operation, list(result["unknowns"]) + [
                str(report.get("error") or "PythoC compilation failed")],
                execution=result, backend_report=report)
        if not ir_path.is_file() or ir_path.is_symlink():
            return _failure(operation, ["PythoC success report has no regular LLVM artifact"],
                            execution=result)
        source_identity = sha256_file(source)
        if report.get("source_sha256") != source_identity or report.get("ir_sha256") != sha256_file(ir_path):
            return _failure(operation, ["PythoC worker artifact identity mismatch"],
                            execution=result)
        read_text(ir_path, encoding="utf-8")
        artifacts = [artifact_record(root, source, "pythoc-source"),
                     artifact_record(root, ir_path, "llvm-ir"),
                     artifact_record(root, report_path, "backend-report")]
        unknowns = ["native behavior, memory safety, and user intent remain unverified"]
        ir_analysis = None
        if analyze:
            version = _llvm_major(report.get("llvm_version"))
            if version is None:
                unknowns.append("PythoC reported an unrecognized LLVM version")
            else:
                ir_analysis = analyze_ir(str(ir_path), version)
                unknowns.extend(ir_analysis["unknowns"])
        return {"schema": SCHEMA, "schema_version": 1, "backend": "pythoc",
                "backend_identity": {key: report.get(key) for key in (
                    "pythoc_module_version", "pythoc_distribution_version", "llvm_version")},
                "operation": operation, "status": "compiled", "verdict": "unknown",
                "candidate": True, "staged": True, "promotion_allowed": False,
                "source_sha256": source_identity, "entrypoint": entrypoint,
                "artifacts": artifacts, "ir_analysis": ir_analysis,
                "llvm_ir_verified": report.get("llvm_ir_verified") is True,
                "verification_scope": "LLVM well-formedness and optionally parsed CFG only",
                "unknowns": sorted(set(unknowns)), "assumptions": [],
                "execution": {"argv_only": True, "sandbox": True, "no_network": True,
                              "no_credentials": True}}
    except (OSError, UnicodeError, ValueError, TypeError) as error:
        return _failure(operation, [f"{type(error).__name__}: {error}"])


def differential_native(before_path: str, after_path: str, argv: list[str], *,
                        files: dict | None = None, target_name: str | None = None,
                        timeout_ms: int = 5000, memory_mb: int = 256) -> dict:
    """Replay two native candidates in separate ephemeral no-network sandboxes."""
    try:
        from ..repairloop import sandboxed_differential
        report = sandboxed_differential(before_path, after_path, argv=argv, files=files,
                                        target_name=target_name, timeout_ms=timeout_ms,
                                        memory_mb=memory_mb)
        return {"schema": SCHEMA, "schema_version": 1, "backend": "pythoc",
                "operation": "differential", "status": report.get("status", "unknown"),
                "verdict": report.get("verdict", "unknown"), "candidate": True,
                "differential": report, "unknowns": report.get("unknowns") or [],
                "assumptions": ["the supplied argv harness compares the intended native entrypoint"],
                "scope": "bounded observations only; matching executions do not prove equivalence"}
    except (OSError, ValueError, TypeError) as error:
        return _failure("differential", [f"{type(error).__name__}: {error}"])
