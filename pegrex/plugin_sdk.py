"""Versioned, deliberately small plugin SDK and conformance checks."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Any

SDK_VERSION = "1.0"
PLUGIN_API_SCHEMA = "pegrex.plugin.v1"
PLUGIN_WORKER_SCHEMA = "pegrex.plugin-worker.v1"
_REQUIRED = {"id", "api_version", "capabilities", "analyze"}

@dataclass(frozen=True)
class PluginDescriptor:
    id: str
    api_version: str
    capabilities: tuple[str, ...]
    analyze: Callable


def validate_plugin(plugin: Any) -> list[str]:
    errors = []
    if isinstance(plugin, dict):
        missing = _REQUIRED - set(plugin)
        if missing: errors.append("missing keys: " + ", ".join(sorted(missing)))
        get = plugin.get
    else:
        missing = [key for key in _REQUIRED if not hasattr(plugin, key)]
        if missing: errors.append("missing attributes: " + ", ".join(sorted(missing)))
        get = lambda key, default=None: getattr(plugin, key, default)
    if get("api_version") != SDK_VERSION: errors.append(f"unsupported plugin API version; expected {SDK_VERSION}")
    if not isinstance(get("id"), str) or not get("id", "").strip(): errors.append("plugin id must be non-empty")
    if not isinstance(get("capabilities"), (list, tuple, set)): errors.append("capabilities must be a sequence")
    if not callable(get("analyze")): errors.append("analyze must be callable")
    return errors


def conformance_test(plugin: Any) -> dict:
    errors = validate_plugin(plugin)
    if errors: return {"schema": PLUGIN_API_SCHEMA, "passed": False, "errors": errors, "tests": 0}
    fn = plugin["analyze"] if isinstance(plugin, dict) else plugin.analyze
    tests = []
    for source in ("", "# unicode: café\n", "def f(:\n pass\n"):
        try:
            result = fn(source)
            ok = isinstance(result, dict) and ("findings" in result or "status" in result or "unknowns" in result)
            tests.append({"case": "empty" if not source else "unicode" if "café" in source else "invalid-syntax", "passed": ok})
        except Exception as exc:
            tests.append({"case": "empty" if not source else "unicode" if "café" in source else "invalid-syntax", "passed": False, "error_type": type(exc).__name__})
    return {"schema": PLUGIN_API_SCHEMA, "plugin_id": plugin["id"] if isinstance(plugin, dict) else plugin.id,
            "passed": all(row["passed"] for row in tests), "tests": len(tests), "results": tests, "errors": []}


def _container_command(plugin_root, module: str, *, image: str, container_name: str,
                       docker_binary: str = "docker") -> list[str]:
    """Build a no-network, read-only Docker invocation for a plugin worker."""
    import re
    from pathlib import Path
    root = Path(plugin_root).resolve(strict=True)
    if not root.is_dir():
        raise ValueError("plugin_root must be a directory")
    if "," in str(root):
        raise ValueError("plugin_root paths containing commas cannot be safely represented in Docker mount syntax")
    if not re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", module):
        raise ValueError("plugin module must be a dotted Python identifier")
    if not isinstance(image, str) or not image.strip() or any(ch.isspace() for ch in image) or image.startswith("-"):
        raise ValueError("image must be an explicit trusted Docker image reference")
    script = (
        "import importlib,json,sys; sys.path.insert(0,'/plugin'); "
        "payload=json.load(sys.stdin); plugin=importlib.import_module(sys.argv[1]); "
        "result=plugin.analyze(payload['source']); "
        "print(json.dumps(result,ensure_ascii=False,separators=(',',':'),default=str))"
    )
    return [docker_binary, "run", "--rm", "--name", container_name,
            "--network", "none", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "64",
            "--memory", "256m", "--cpus", "1", "--read-only",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m",
            "--user", "65534:65534",
            "--mount", f"type=bind,src={root},dst=/plugin,readonly",
            "--workdir", "/plugin", "--env", "PYTHONDONTWRITEBYTECODE=1",
            image, "python", "-I", "-c", script, module]


def run_plugin_containerized(plugin_root, module: str, source: str, *,
                             image: str = "python:3.12-slim",
                             timeout_seconds: float = 5.0,
                             max_input_bytes: int = 1_000_000,
                             max_output_bytes: int = 1_000_000,
                             docker_binary: str = "docker") -> dict:
    """Run an importable plugin in a restricted disposable Docker container.

    This requires a trusted, prebuilt image containing the plugin's dependencies.
    Only the selected plugin directory is mounted, read-only; there are no network
    interfaces, secrets, or Docker socket mounts. The host Docker daemon/kernel
    remain part of the trusted computing base, so this is not a VM boundary.
    """
    import json
    import os
    import selectors
    import shutil
    import signal
    import subprocess
    import time
    import uuid

    if not isinstance(source, str):
        return {"schema": PLUGIN_WORKER_SCHEMA, "status": "unknown", "reason": "source must be text"}
    if timeout_seconds <= 0 or max_input_bytes < 1 or max_output_bytes < 1:
        return {"schema": PLUGIN_WORKER_SCHEMA, "status": "unknown", "reason": "invalid resource budget"}
    payload = json.dumps({"source": source}, ensure_ascii=False).encode("utf-8")
    if len(payload) > max_input_bytes:
        return {"schema": PLUGIN_WORKER_SCHEMA, "status": "unknown", "reason": "plugin input budget exceeded"}
    binary = shutil.which(docker_binary)
    if binary is None:
        return {"schema": PLUGIN_WORKER_SCHEMA, "status": "unknown", "reason": "container runtime unavailable"}
    container_name = "pegrex-plugin-" + uuid.uuid4().hex[:20]
    try:
        command = _container_command(plugin_root, module, image=image,
                                    container_name=container_name, docker_binary=binary)
    except (OSError, ValueError) as exc:
        return {"schema": PLUGIN_WORKER_SCHEMA, "status": "unknown", "reason": type(exc).__name__}
    try:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
    except OSError as exc:
        return {"schema": PLUGIN_WORKER_SCHEMA, "status": "unknown", "reason": type(exc).__name__}

    selector = selectors.DefaultSelector()
    assert process.stdin is not None and process.stdout is not None and process.stderr is not None
    for stream, event, name in ((process.stdin, selectors.EVENT_WRITE, "stdin"),
                                (process.stdout, selectors.EVENT_READ, "stdout"),
                                (process.stderr, selectors.EVENT_READ, "stderr")):
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, event, name)
    offset = 0
    output = bytearray()
    stderr_bytes = 0
    deadline = time.monotonic() + timeout_seconds
    failure = None
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "timeout"
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                stream = key.fileobj
                if key.data == "stdin":
                    if offset >= len(payload):
                        selector.unregister(stream); stream.close(); continue
                    try:
                        offset += os.write(stream.fileno(), payload[offset:offset + 65536])
                    except BrokenPipeError:
                        selector.unregister(stream); stream.close()
                else:
                    try:
                        chunk = os.read(stream.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream); stream.close(); continue
                    if key.data == "stdout":
                        output.extend(chunk)
                    else:
                        stderr_bytes += len(chunk)
                    if len(output) + stderr_bytes > max_output_bytes:
                        failure = "output_limit"
                        break
            if failure:
                break
            if process.poll() is not None and not selector.get_map():
                break
    finally:
        selector.close()
    if failure:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=2)
        try:
            subprocess.run([binary, "rm", "-f", container_name], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
        return {"schema": PLUGIN_WORKER_SCHEMA, "status": "unknown",
                "reason": "plugin execution timed out" if failure == "timeout" else "plugin output budget exceeded"}
    try:
        return_code = process.wait(timeout=max(0.1, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            process.kill()
        process.wait(timeout=2)
        try:
            subprocess.run([binary, "rm", "-f", container_name], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
        return {"schema": PLUGIN_WORKER_SCHEMA, "status": "unknown", "reason": "plugin execution timed out"}
    if return_code != 0:
        return {"schema": PLUGIN_WORKER_SCHEMA, "status": "unknown", "reason": "plugin worker failed",
                "exit_code": return_code, "stderr_bytes": stderr_bytes}
    try:
        result = json.loads(output.decode("utf-8"))
    except (UnicodeError, ValueError):
        return {"schema": PLUGIN_WORKER_SCHEMA, "status": "unknown", "reason": "plugin returned invalid JSON"}
    if not isinstance(result, dict):
        return {"schema": PLUGIN_WORKER_SCHEMA, "status": "unknown", "reason": "plugin result must be an object"}
    return {"schema": PLUGIN_WORKER_SCHEMA, "status": "ok", "result": result,
            "containerized": True, "network_disabled": True, "read_only_plugin_mount": True}
