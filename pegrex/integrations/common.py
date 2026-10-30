"""Shared bounded I/O, artifact provenance, and argv-only process execution."""
from __future__ import annotations

import hashlib
import json
import math
import os
from pathlib import Path
import shutil
import signal
import subprocess
import threading
import tempfile
import stat
from typing import Any

from . import SCHEMA

MAX_INPUT_BYTES = 2_000_000
MAX_OUTPUT_BYTES = 8_000_000
MAX_ARTIFACT_BYTES = 20_000_000


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: str | Path, *, max_bytes: int = MAX_ARTIFACT_BYTES) -> str:
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            if size > max_bytes:
                raise ValueError(f"file exceeds hash budget: {path}")
            digest.update(chunk)
    return digest.hexdigest()


def read_bytes(path: str | Path, *, max_bytes: int = MAX_INPUT_BYTES) -> bytes:
    """Read a bounded regular file without following symlinks where supported."""
    if not isinstance(max_bytes, int) or isinstance(max_bytes, bool) or max_bytes < 0:
        raise ValueError("max_bytes must be a nonnegative integer")
    candidate = Path(path)
    if candidate.is_symlink() or not candidate.is_file():
        raise ValueError(f"expected a regular non-symlink file: {candidate}")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    # Binary descriptor-level open prevents implicit text decoding and allows
    # O_NOFOLLOW to close the symlink race between pre-check and open.
    try:
        descriptor = os.open(candidate, flags)
    except OSError as error:
        raise ValueError(f"unable to open regular input file: {candidate}") from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"expected a regular non-symlink file: {candidate}")
        if metadata.st_size > max_bytes:
            raise ValueError(f"input exceeds {max_bytes} bytes: {candidate}")
        chunks = bytearray()
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while len(chunks) <= max_bytes:
                block = stream.read(min(64 * 1024, max_bytes + 1 - len(chunks)))
                if not block:
                    break
                chunks.extend(block)
        if len(chunks) > max_bytes:
            raise ValueError(f"input exceeds {max_bytes} bytes: {candidate}")
        return bytes(chunks)
    finally:
        os.close(descriptor)


def read_text(path: str | Path, *, encoding: str = "utf-8",
              max_bytes: int = MAX_INPUT_BYTES) -> str:
    return read_bytes(path, max_bytes=max_bytes).decode(encoding)


def read_json(path: str | Path, *, max_bytes: int = MAX_INPUT_BYTES) -> Any:
    return json.loads(read_text(path, encoding="utf-8", max_bytes=max_bytes))


def write_json(path: str | Path, value: Any) -> None:
    """Atomically write JSON without following an attacker-controlled temp link."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise ValueError(f"refusing symlink output: {path}")
    payload = json.dumps(value, indent=2, sort_keys=True,
                         ensure_ascii=False, allow_nan=False) + "\n"
    temporary_name = None
    try:
        with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", newline="\n", dir=path.parent,
                prefix=f".{path.name}.", suffix=".tmp", delete=False) as stream:
            temporary_name = stream.name
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        if temporary_name:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def prepare_staging(path: str | Path, *, max_entries: int = 4096) -> Path:
    """Create/validate staging and reject symlinks before any writes occur."""
    if not isinstance(max_entries, int) or isinstance(max_entries, bool) or max_entries < 1:
        raise ValueError("max_entries must be a positive integer")
    root = Path(path)
    if root.is_symlink():
        raise ValueError("staging root must not be a symbolic link")
    root.mkdir(parents=True, exist_ok=True)
    resolved = root.resolve()
    if not resolved.is_dir():
        raise ValueError("staging root must be a directory")
    entries = 0
    for candidate in resolved.rglob("*"):
        entries += 1
        if entries > max_entries:
            raise ValueError("staging entry-count budget exhausted")
        if candidate.is_symlink():
            raise ValueError(f"staging contains a symbolic link: {candidate.relative_to(resolved)}")
    return resolved


def contained(root: str | Path, path: str | Path) -> Path:
    root = Path(root).resolve()
    candidate = Path(path)
    if candidate.is_symlink():
        raise ValueError(f"symbolic-link artifact refused: {path}")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"artifact escapes staging root: {path}") from error
    return resolved


def artifact_record(root: str | Path, path: str | Path, kind: str) -> dict:
    root = Path(root).resolve()
    candidate = Path(path)
    if candidate.is_symlink():
        raise ValueError(f"artifact must be a regular non-symlink file: {path}")
    resolved = contained(root, candidate)
    if not resolved.is_file():
        raise ValueError(f"artifact must be a regular non-symlink file: {path}")
    return {"kind": kind, "path": resolved.relative_to(root).as_posix(),
            "sha256": sha256_file(resolved), "bytes": resolved.stat().st_size}


def collect_artifacts(root: str | Path, *, kinds: dict[str, str] | None = None,
                      max_files: int = 128) -> list[dict]:
    if not isinstance(max_files, int) or isinstance(max_files, bool) or max_files < 1:
        raise ValueError("max_files must be a positive integer")
    if kinds is not None and (not isinstance(kinds, dict) or
                              any(not isinstance(key, str) or not isinstance(value, str)
                                  for key, value in kinds.items())):
        raise ValueError("kinds must map file suffix strings to kind strings")
    root_path = Path(root)
    if root_path.is_symlink() or not root_path.is_dir():
        raise ValueError("artifact root must be a regular directory, not a symlink")
    root = root_path.resolve()
    rows = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symbolic-link artifact refused: {path}")
        if not path.is_file() or path.name.endswith(".tmp"):
            continue
        if len(rows) >= max_files:
            raise ValueError("integration artifact count budget exhausted")
        kind = (kinds or {}).get(path.suffix, "file")
        rows.append(artifact_record(root, path, kind))
    return rows


def backend_identity(distribution: str, *, executable: str | None = None) -> dict:
    from importlib.metadata import PackageNotFoundError, version
    try:
        package_version = version(distribution)
    except PackageNotFoundError:
        package_version = None
    return {"distribution": distribution, "version": package_version,
            "executable": executable,
            "executable_sha256": sha256_file(executable) if executable and Path(executable).is_file() else None}


def unknown_result(backend: str, operation: str, unknowns: list[str], **extra) -> dict:
    return {"schema": SCHEMA, "schema_version": 1, "backend": backend,
            "operation": operation, "status": "unknown", "verdict": "unknown",
            "candidate": True, "artifacts": [], "unknowns": sorted(set(unknowns)),
            "assumptions": [], **extra}


def validate_argv(argv: Any) -> list[str]:
    if isinstance(argv, str) or not isinstance(argv, (list, tuple)) or not argv:
        raise ValueError("external execution requires a nonempty argv array")
    if any(not isinstance(row, str) or not row or "\x00" in row for row in argv):
        raise ValueError("every argv entry must be a nonempty NUL-free string")
    return list(argv)


def _limits(timeout_ms: int, memory_mb: int):
    def set_limits():
        import resource
        resource.setrlimit(resource.RLIMIT_CPU,
                           (max(1, math.ceil(timeout_ms / 1000)),) * 2)
        resource.setrlimit(resource.RLIMIT_AS, (memory_mb * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
        resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_ARTIFACT_BYTES,) * 2)
    return set_limits


def _sandbox_argv(argv: list[str], cwd: Path, timeout_ms: int, memory_mb: int) -> list[str]:
    bwrap, prlimit = shutil.which("bwrap"), shutil.which("prlimit")
    if not bwrap or not prlimit or os.name != "posix":
        raise RuntimeError("ephemeral isolated sandbox unavailable")
    command = [bwrap, "--unshare-all", "--die-with-parent", "--new-session",
               "--clearenv", "--cap-drop", "ALL", "--tmpfs", "/", "--proc", "/proc",
               "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/home",
               "--tmpfs", "/root"]
    for directory in ("/usr", "/usr/local", "/lib", "/lib64", "/bin", "/sbin"):
        if Path(directory).exists():
            command += ["--ro-bind", directory, directory]
    command += ["--bind", str(cwd), "/workspace", "--chdir", "/workspace",
                "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
                "--setenv", "PYTHONDONTWRITEBYTECODE", "1", "--",
                prlimit, f"--cpu={max(1, math.ceil(timeout_ms / 1000))}",
                f"--as={memory_mb * 1024 * 1024}", "--nofile=128",
                f"--fsize={MAX_ARTIFACT_BYTES}", "--"] + argv
    return command


def run_argv(argv: list[str], *, cwd: str | Path, timeout_ms: int = 30_000,
             memory_mb: int = 512, sandbox: bool = False,
             max_output_bytes: int = MAX_OUTPUT_BYTES,
             extra_env: dict[str, str] | None = None) -> dict:
    """Execute argv without a shell and with bounded output buffering.

    Output is drained continuously but only ``max_output_bytes + 1`` bytes are
    retained. This avoids unbounded temporary-file growth from noisy children
    on platforms where POSIX resource limits are unavailable.
    """
    try:
        argv = validate_argv(argv)
        if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or not 1 <= timeout_ms <= 300_000:
            raise ValueError("timeout_ms must be between 1 and 300000")
        if not isinstance(memory_mb, int) or isinstance(memory_mb, bool) or not 16 <= memory_mb <= 8192:
            raise ValueError("memory_mb must be between 16 and 8192")
        if (not isinstance(max_output_bytes, int) or isinstance(max_output_bytes, bool)
                or not 0 <= max_output_bytes <= MAX_OUTPUT_BYTES):
            raise ValueError(f"max_output_bytes must be between 0 and {MAX_OUTPUT_BYTES}")
        workspace = Path(cwd).resolve()
        if not workspace.is_dir():
            raise ValueError("execution working directory does not exist")
        if sandbox and extra_env:
            raise ValueError("extra_env is forbidden for sandboxed execution")
        plan = _sandbox_argv(argv, workspace, timeout_ms, memory_mb) if sandbox else argv
        environment = {"PATH": "/usr/local/bin:/usr/bin:/bin",
                       "PYTHONDONTWRITEBYTECODE": "1"}
        if extra_env:
            if any(not isinstance(key, str) or not key or "=" in key or "\x00" in key
                   or not isinstance(value, str) or "\x00" in value
                   for key, value in extra_env.items()):
                raise ValueError("environment keys/values must be valid NUL-free strings")
            environment.update(extra_env)
        if sandbox:
            # Sandboxed processes receive no caller-provided environment.
            environment = {}
        preexec = None if sandbox or os.name != "posix" else _limits(timeout_ms, memory_mb)
        process = subprocess.Popen(
            plan, cwd=workspace if not sandbox else None, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=environment,
            start_new_session=(os.name == "posix"), preexec_fn=preexec)
        captured = bytearray()
        output_error: list[BaseException] = []

        def drain_output() -> None:
            try:
                assert process.stdout is not None
                while True:
                    chunk = os.read(process.stdout.fileno(), 64 * 1024)
                    if not chunk:
                        break
                    remaining = max_output_bytes + 1 - len(captured)
                    if remaining > 0:
                        captured.extend(chunk[:remaining])
            except BaseException as error:
                output_error.append(error)

        reader = threading.Thread(target=drain_output, name="pegrex-output-drain", daemon=True)
        reader.start()
        try:
            process.wait(timeout=timeout_ms / 1000)
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            else:
                process.kill()
            process.wait()
            reader.join(timeout=2)
            return {"status": "timeout", "executed": True, "confirmed": False,
                    "returncode": None, "evidence": "",
                    "unknowns": [f"external operation timed out after {timeout_ms} ms"],
                    "sandbox": sandbox}
        reader.join(timeout=2)
        if reader.is_alive():
            return {"status": "unknown", "executed": True, "confirmed": False,
                    "returncode": process.returncode, "evidence": "",
                    "unknowns": ["external output reader did not terminate"],
                    "sandbox": sandbox}
        if output_error:
            return {"status": "unknown", "executed": True, "confirmed": False,
                    "returncode": process.returncode, "evidence": "",
                    "unknowns": [f"output capture failed: {type(output_error[0]).__name__}"],
                    "sandbox": sandbox}
        truncated = len(captured) > max_output_bytes
        evidence = bytes(captured[:max_output_bytes]).decode("utf-8", errors="replace")
        setup_failed = bool(process.returncode and sandbox and
                            evidence.lstrip().startswith(("bwrap:", "prlimit:")))
        unknowns = []
        if truncated:
            unknowns.append("external operation output was truncated")
        if setup_failed:
            unknowns.append("isolated sandbox setup failed; payload execution was not established")
        status = ("unavailable" if setup_failed else
                  "failed" if process.returncode != 0 else
                  "unknown" if truncated else "completed")
        return {"status": status, "executed": not setup_failed,
                "confirmed": process.returncode == 0 and not truncated,
                "returncode": process.returncode, "evidence": evidence,
                "unknowns": unknowns, "sandbox": sandbox}
    except (OSError, RuntimeError, ValueError) as error:
        return {"status": "unavailable", "executed": False, "confirmed": False,
                "returncode": None, "evidence": "",
                "unknowns": [f"{type(error).__name__}: {error}"], "sandbox": sandbox}

