"""
harness - formal safety harness for coding agents

Agent plans are lists of actions ({tool, args} or {tool, argv}); policies are
allow/deny rules over tools, normalized paths, and structured argv. Shell tool
actions accept *only* argv. There is deliberately no raw-shell-text parser:
quoting cannot turn control operators, expansion, or redirection into safe
syntax. Deny rules win and unknown tools are default-denied before execution.
"""

from __future__ import annotations

import fnmatch
import ntpath
import pathlib
import posixpath
import re
import shlex
import unicodedata

_SHELL_META = re.compile(r"[\x00\r\n;&|`$><]")
_WINDOWS_EXPANSION = re.compile(r"%[^%\r\n]+%|![^!\r\n]+!")
_EXECUTABLE = re.compile(r"^[a-z0-9][a-z0-9._+-]*$")
_SHELLS = {
    "sh", "bash", "dash", "zsh", "fish", "ksh", "csh", "tcsh",
    "cmd", "powershell", "pwsh",
}
# These programs can turn one authorized executable into a second, unexamined
# executable. Policies must authorize the real operation instead.
_LAUNCHERS = {
    "busybox", "command", "doas", "env", "nice", "nohup", "setsid",
    "stdbuf", "sudo", "timeout", "xargs",
}
_EXECUTABLE_ALIASES = {"py.test": "pytest"}


def default_policy():
    return [
        {"effect": "deny", "tool": "shell", "args": "*rm -rf*"},
        {"effect": "deny", "tool": "shell", "args": "*curl* *|*sh*"},
        {"effect": "deny", "tool": "write", "path": "*.pem"},
        {"effect": "deny", "tool": "write", "path": ".*"},
        {"effect": "deny", "tool": "shell", "args": "git push*"},
        {"effect": "allow", "tool": "read"},
        {"effect": "allow", "tool": "write", "path": "src/*"},
        {"effect": "allow", "tool": "shell", "executable": "pytest"},
        {"effect": "allow", "tool": "shell", "executable": "git",
         "argv_prefix": ["status"]},
    ]


def _ascii_nfkc(value: str, label: str) -> str:
    """Return one unambiguous policy identity, never a confusable lookalike."""
    normalized = unicodedata.normalize("NFKC", value)
    if normalized != value or not value.isascii():
        raise ValueError(f"{label} must be canonical ASCII (Unicode confusables refused)")
    return normalized


def _canonical_executable(executable: str) -> str:
    executable = _ascii_nfkc(executable, "executable").lower()
    if executable.endswith(".exe"):
        executable = executable[:-4]
    executable = _EXECUTABLE_ALIASES.get(executable, executable)
    if not _EXECUTABLE.fullmatch(executable):
        raise ValueError("executable must be a direct, unadorned executable name")
    return executable


def _absolute_or_home_path(token: str) -> bool:
    return (token.startswith("~") or posixpath.isabs(token)
            or ntpath.isabs(token) or bool(ntpath.splitdrive(token)[0]))


def normalize_argv(argv) -> list[str]:
    """Validate and canonicalize one direct execution, with no shell involved.

    The returned list is the only executable identity policies may authorize.
    Metacharacters are rejected even when quoted because there is no shell
    context in which a quote could make them meaningful.
    """
    if (not isinstance(argv, (list, tuple)) or not argv
            or any(not isinstance(token, str) or not token for token in argv)):
        raise ValueError("shell argv must be a non-empty string list")
    normalized = [_ascii_nfkc(token, "argv token") for token in argv]
    if any(_SHELL_META.search(token) or _WINDOWS_EXPANSION.search(token)
           for token in normalized):
        raise ValueError("shell control, expansion, and redirection are forbidden")
    if any(_absolute_or_home_path(token) for token in normalized):
        raise ValueError("absolute, drive-qualified, UNC, and home paths are forbidden")
    executable = _canonical_executable(normalized[0])
    if "/" in executable or "\\" in executable or executable in _SHELLS | _LAUNCHERS:
        raise ValueError("shell action requires a direct non-shell, non-launcher executable")
    return [executable, *normalized[1:]]


def _shell_argv(action):
    """Return one safe argv; raw shell text is never an accepted input."""
    if "argv" not in action:
        raise ValueError("shell actions require structured argv; raw shell text is forbidden")
    if "args" in action:
        raise ValueError("shell action must use argv only, not raw args")
    return normalize_argv(action["argv"])


def _normalized_path(action, base_dir=None) -> str:
    raw = action.get("path")
    if not raw:
        return ""
    if not isinstance(raw, str):
        raise ValueError("path must be text")
    raw = _ascii_nfkc(raw, "path")
    if "\x00" in raw or _absolute_or_home_path(raw):
        raise ValueError("absolute, drive-qualified, UNC, home, and NUL paths are forbidden")
    # Backslashes are path separators for policy purposes on every host, so a
    # Windows spelling cannot bypass a POSIX policy (or vice versa).
    portable = raw.replace("\\", "/")
    if any(part == ".." for part in portable.split("/")):
        raise ValueError("parent-directory traversal is forbidden")
    normalized = posixpath.normpath(portable)
    if normalized in ("", ".", "..") or normalized.startswith("../"):
        raise ValueError("path must name an entry beneath the workspace")

    root = pathlib.Path(base_dir) if base_dir is not None else pathlib.Path.cwd()
    candidate = root.joinpath(*normalized.split("/"))
    current = root
    for part in pathlib.PurePosixPath(normalized).parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"symbolic-link path component refused: {normalized}")
    # Also protect against a base-directory switch and platform-specific path
    # interpretation. Existing symlinks were refused above; this is a second
    # containment check, not a claim of race-free filesystem mutation.
    root_resolved = root.resolve()
    candidate_resolved = candidate.resolve(strict=False)
    try:
        candidate_resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError("path escapes the workspace") from exc
    return normalized


def _rule_matches(rule, tool, args, path, argv):
    if not fnmatch.fnmatchcase(tool, rule.get("tool", "")):
        return False
    if rule.get("args") and not fnmatch.fnmatchcase(args, rule["args"]):
        return False
    if rule.get("path") and not fnmatch.fnmatchcase(path, rule["path"]):
        return False
    if "executable" in rule:
        try:
            expected = _canonical_executable(rule["executable"])
        except (TypeError, ValueError):
            return False
        if not argv or argv[0] != expected:
            return False
    if "argv_prefix" in rule and (not argv or argv[:len(rule["argv_prefix"])] != rule["argv_prefix"]):
        return False
    if "argv" in rule:
        expected = rule["argv"]
        if not argv or len(argv) != len(expected) or any(
                not fnmatch.fnmatchcase(got, wanted)
                for got, wanted in zip(argv, expected)):
            return False
    return True


def check_action(action, policy, *, base_dir=None):
    """Check one action without executing it, using default-deny semantics."""
    tool = action.get("tool", "")
    if not isinstance(tool, str):
        return {"action": action, "verdict": "refused", "reason": "tool must be text"}
    try:
        tool = _ascii_nfkc(tool, "tool")
        path = _normalized_path(action, base_dir)
    except ValueError as exc:
        return {"action": action, "verdict": "refused", "reason": str(exc)}
    argv = None
    if tool == "shell":
        try:
            argv = _shell_argv(action)
            args = shlex.join(argv)
        except ValueError as exc:
            return {"action": action, "verdict": "refused", "reason": str(exc)}
    else:
        args = action.get("args", "")
        if not isinstance(args, str):
            return {"action": action, "verdict": "refused",
                    "reason": "args must be text"}
    decision, rule_i = None, None
    for i, rule in enumerate(policy):
        if not _rule_matches(rule, tool, args, path, argv):
            continue
        if rule["effect"] == "deny":
            return {"action": action, "verdict": "refused",
                    "reason": f"deny rule #{i}"}
        if decision is None:
            decision, rule_i = "allowed", i
    if decision:
        return {"action": action, "verdict": "allowed", "rule": rule_i,
                **({"argv": argv} if argv is not None else {}),
                **({"path": path} if path else {})}
    return {"action": action, "verdict": "refused",
            "reason": "no allow rule matched (default-deny)"}


def check_plan(plan, policy=None, *, base_dir=None):
    """Check before execution. The first refusal stops the plan."""
    policy = policy or default_policy()
    verdicts = []
    for action in plan:
        verdict = check_action(action, policy, base_dir=base_dir)
        verdicts.append(verdict)
        if verdict["verdict"] == "refused":
            break
    return {"safe": all(v["verdict"] == "allowed" for v in verdicts)
            and len(verdicts) == len(plan),
            "verdicts": verdicts}
