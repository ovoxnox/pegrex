"""
harness - formal safety harness for coding agents

Agent plans are lists of actions ({tool, args}); policies are allow/deny
rules with globs over tools, paths, and command text. Every action is
checked before anything runs: in-policy -> allowed, matching deny or
unknown tool -> refused with the rule that fired. Refusal happens before
execution -- the plan never partially runs."""

from __future__ import annotations

import fnmatch
import posixpath


def default_policy():
    return [
        {"effect": "deny", "tool": "shell", "args": "*rm -rf*"},
        {"effect": "deny", "tool": "shell", "args": "*curl* *|*sh*"},
        {"effect": "deny", "tool": "write", "path": "*.pem"},
        {"effect": "deny", "tool": "write", "path": ".*"},
        {"effect": "deny", "tool": "shell", "args": "git push*"},
        {"effect": "allow", "tool": "read"},
        {"effect": "allow", "tool": "write", "path": "src/*"},
        {"effect": "allow", "tool": "shell", "args": "pytest*"},
        {"effect": "allow", "tool": "shell", "args": "git status*"},
    ]


def check_action(action, policy):
    """One action -> verdict dict. Deny matches win; else any allow.
    No matching rule -> refused (default-deny).

    Paths are matched against the normalized form (posixpath.normpath):
    plain fnmatch treats '/' as an ordinary character, so a glob like
    'src/*' matches 'src/../../../etc/passwd' literally -- the '..'
    segments are just more characters to '*', not a directory escape.
    Normalizing first closes that path-traversal hole; a path rule can
    only ever match what it looks like it matches."""
    tool = action.get("tool", "")
    args = action.get("args", "")
    path = posixpath.normpath(action["path"]) if action.get("path") else ""
    decision, rule_i = None, None
    for i, r in enumerate(policy):
        if not fnmatch.fnmatchcase(tool, r.get("tool", "")):
            continue
        if r.get("args") and not fnmatch.fnmatchcase(args, r["args"]):
            continue
        if r.get("path") and not fnmatch.fnmatchcase(path, r["path"]):
            continue
        if r["effect"] == "deny":
            return {"action": action, "verdict": "refused",
                    "reason": f"deny rule #{i}"}
        if decision is None:
            decision, rule_i = "allowed", i
    if decision:
        return {"action": action, "verdict": "allowed", "rule": rule_i}
    return {"action": action, "verdict": "refused",
            "reason": "no allow rule matched (default-deny)"}


def check_plan(plan, policy=None):
    """Check before execution. The first refusal stops 
                                   the plan: nothing after it runs."""
    policy = policy or default_policy()
    verdicts = []
    for a in plan:
        v = check_action(a, policy)
        verdicts.append(v)
        if v["verdict"] == "refused":
            break
    return {"safe": all(v["verdict"] == "allowed" for v in verdicts)
            and len(verdicts) == len(plan),
            "verdicts": verdicts}
