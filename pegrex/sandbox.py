"""
sandbox - subprocess-isolated candidate execution for the CEGIS chain

Candidates are untrusted code: an infinite loop, a memory bomb, or an
import-time crash must never take the parent process down. The candidate
never runs through eval/exec in the parent: it is written to a fresh
tempfile.TemporaryDirectory and executed under [sys.executable, "-I",
"-S"] with rlimits (CPU seconds, address space, file descriptors) set in
the child's preexec_fn, stdout/stderr captured, and a wall-clock
communicate timeout. Three-valued, loud refusals: ok / timeout / crash.

Isolation claims are Linux-only. sandbox_available() is False anywhere
else, and every entry point refuses (SandboxError) rather than silently
falling back to in-process execution -- a fake "sandbox" would be worse
than no sandbox."""

from __future__ import annotations

import ast
import json
import math
import os
import subprocess
import sys
import tempfile


class SandboxError(ValueError):
    """Isolation unavailable or candidate environment broken -- loud
    refusal, never a silent in-process fallback."""


def sandbox_available() -> bool:
    """True only where the isolation claim is real: a posix OS with the
    resource module (rlimits). Everything else: False -> callers must refuse, not pretend."""
    if os.name != "posix":
        return False
    try:
        import resource
        return True
    except ImportError:
        return False


_WRAPPER = r'''
import importlib.util, json, sys

def _main():
    spec = importlib.util.spec_from_file_location("candidate", "candidate.py")
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as e:
        print("CANDIDATE-IMPORT-ERROR: %s: %s" % (type(e).__name__, e),
              file=sys.stderr)
        sys.exit(3)
    try:
        with open("data.json") as f:
            data = json.load(f)
        mod.DATA = data.get("data")
        fn = getattr(mod, data["fn_name"])
        result = fn(*data["args"])
    except Exception as e:
        print("CANDIDATE-RUNTIME-ERROR: %s: %s" % (type(e).__name__, e),
              file=sys.stderr)
        sys.exit(4)
    try:
        line = json.dumps({"result": result})
    except (TypeError, ValueError):
        line = json.dumps({"result": repr(result)})   # repr for non-JSON
    print(line)

_main()
'''


def _limits(timeout, mem_mb):
    import resource

    def _set():
        resource.setrlimit(resource.RLIMIT_CPU,
                           (max(1, math.ceil(timeout)),) * 2)
        resource.setrlimit(resource.RLIMIT_AS, (mem_mb * 1024 * 1024,) * 2)
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    return _set


def run_python_isolated(src, fn_name, args: list, timeout=5.0, mem_mb=256,
                        argv_data=None) -> dict:
    """Run candidate src's fn(*args) in a rlimited subprocess.

    Returns one of:
      {"ok": True,  "result": ...}                  -- JSON line parsed
      {"ok": False, "refused": "timeout after Ns -- candidate did not
                    terminate", "kind": "timeout"}  -- killed, parent fine
      {"ok": False, "error": <stderr tail>, "kind": "crash"}
                                                   -- nonzero exit (raised,
                                                      killed by rlimits, or
                                                      no result line)
    The source is never eval/exec'd in the parent process.
    """
    if not sandbox_available():
        raise SandboxError("refusing to claim isolation on this platform")
    with tempfile.TemporaryDirectory() as td:
        with open(os.path.join(td, "candidate.py"), "w", encoding="utf-8") as f:
            f.write(src)
        with open(os.path.join(td, "wrapper.py"), "w", encoding="utf-8") as f:
            f.write(_WRAPPER)
        with open(os.path.join(td, "data.json"), "w", encoding="utf-8") as f:
            json.dump({"fn_name": fn_name, "args": list(args),
                       "data": argv_data}, f)
        try:
            proc = subprocess.Popen(
                [sys.executable, "-I", "-S", "wrapper.py"],
                cwd=td, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                preexec_fn=_limits(timeout, mem_mb))
        except OSError as e:
            return {"ok": False,
                    "error": f"sandbox spawn failed: {e}", "kind": "crash"}
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
            return {"ok": False,
                    "refused": f"timeout after {timeout}s -- candidate did "
                               f"not terminate",
                    "kind": "timeout"}
        stderr = (err or b"").decode("utf-8", "replace")
        if proc.returncode != 0:
            return {"ok": False,
                    "error": stderr[-500:] or f"exit code {proc.returncode}",
                    "kind": "crash"}
        for line in reversed((out or b"").decode("utf-8", "replace")
                             .splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    return {"ok": True, "result": json.loads(line)["result"]}
                except (ValueError, KeyError):
                    break
        return {"ok": False,
                "error": "candidate produced no JSON result line; stdout: "
                         + (out or b"").decode("utf-8", "replace")[-200:],
                "kind": "crash"}


def _first_def(src):
    """The first top-level def in source order (same rule as chain.py)."""
    try:
        tree = ast.parse(src)
    except SyntaxError as e:
        raise SandboxError(f"sandbox: candidate does not parse: {e}")
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            return node.name
    return None


def _load(src, name):
    """In-process load for the trusted before-source only 
          (the candidate never takes this path)."""
    import importlib.util
    fd, p = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(src)
    spec = importlib.util.spec_from_file_location(name, p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    os.unlink(p)
    return mod


def run_cegis_candidate(candidate_src, before_src, sample_inputs, verifier,
                        timeout=5.0, mem_mb=256) -> dict:
    """Validate a repair candidate under the sandbox, input by input.

    The candidate runs through run_python_isolated (never in-process);
    the trusted before-source runs in-process. For each sampled input,
    verifier(before_result, candidate_result) is consulted (default:
    equality). Returns {"verified": bool, "evidence": [...],
    "disagreements": int} -- every disagreement and every sandbox
    refusal is recorded, never papered over."""
    if not sandbox_available():
        raise SandboxError("refusing to claim isolation on this platform")
    fn_c = _first_def(candidate_src)
    fn_b = _first_def(before_src)
    if fn_c is None or fn_b is None:
        raise SandboxError("sandbox: no top-level function to compare")
    mod_b = _load(before_src, "before_sandbox_mod")
    fn_before = getattr(mod_b, fn_b)
    evidence = []
    disagreements = 0
    for inp in sample_inputs:
        args = [inp[k] for k in sorted(inp)]
        try:
            r_before = fn_before(*args)
        except Exception as e:
            r_before = f"error:{type(e).__name__}"
        run = run_python_isolated(candidate_src, fn_c, args,
                                  timeout=timeout, mem_mb=mem_mb)
        if run["ok"]:
            r_after = run["result"]
            agree = r_before == r_after
            v_pass = verifier(r_before, r_after) if verifier else agree
        else:
            r_after = f"error:{run['kind']}"
            agree, v_pass = False, False
        disagreements += 0 if (agree and v_pass) else 1
        evidence.append({"inputs": inp, "before": r_before, "after": r_after,
                         "agree": agree, "verifier_passed": bool(v_pass),
                         "sandbox_ok": run["ok"]})
    return {"verified": disagreements == 0, "evidence": evidence,
            "disagreements": disagreements}
