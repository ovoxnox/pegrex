"""
╔══════════════════════════════════════════════════════════════════════════╗
║  continuity — verify the engine against its own prior version            ║
║  Compares an OLD and NEW snapshot of a Python package (pegrex itself,    ║
║  or any other), FUNCTION by function, via semantics.verify_patch -- the  ║
║  SAME proof-or-counterexample engine pegrex offers every other           ║
║  codebase, turned on its own evolution. verify_patch/api.contracts are   ║
║  single-function tools (every cert isolates one function per file        ║
║  before calling them); comparing whole multi-function modules directly   ║
║  degenerates into "mostly opaque" noise, so each top-level function      ║
║  present in both snapshots is isolated into its own temp file first --   ║
║  the SAME discipline every other certificate in this engine already      ║
║  follows, just automated across a whole package.                         ║
║  A function behaviorally IDENTICAL across versions is a continuity       ║
║  proof; one with a DISTINGUISHING counterexample is named CHANGED, with  ║
║  the concrete input that tells the two versions apart -- never a vague   ║
║  "something differs". Functions outside the provable fragment are        ║
║  named incomplete, not silently skipped.                                 ║
╚══════════════════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations

import ast
import os
import pathlib
import tempfile
import textwrap

from .semantics import verify_patch


def _top_level_functions(path: pathlib.Path) -> dict:
    """{label: source_text} for every top-level def AND class method in a
    module (methods labeled "ClassName.method_name"). Most of this
    engine's interesting logic lives in class methods (CFGBuilder,
    LinearBackend, Octagon, ...), not bare module-level functions -- only
    extracting the latter would miss most real changes. Source is
    dedented: a method's text is indented in the original file, which
    would be a syntax error once isolated into its own standalone file."""
    src = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(src)
    except SyntaxError:
        return {}
    out = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            seg = ast.get_source_segment(src, node)
            if seg is not None:
                out[node.name] = textwrap.dedent(seg)
        elif isinstance(node, ast.ClassDef):
            for sub in node.body:
                if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    seg = ast.get_source_segment(src, sub)
                    if seg is not None:
                        out[f"{node.name}.{sub.name}"] = textwrap.dedent(seg)
    return out


def _verify_function_patch(before_src: str, after_src: str) -> dict:
    """Isolate each function body into its own temp file (the same
    single-function-per-file discipline every certificate in this engine
    already uses) before handing it to verify_patch."""
    fds = [tempfile.mkstemp(suffix=".py") for _ in range(2)]
    paths = [p for _, p in fds]
    try:
        for (fd, p), src in zip(fds, (before_src, after_src)):
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(src)
        return verify_patch(paths[0], paths[1])
    finally:
        for p in paths:
            os.unlink(p)


def compare_snapshots(old_dir: str, new_dir: str, pattern: str = "*.py") -> dict:
    """Pairwise, per-function verify_patch over every module present in
    both snapshots. Added/removed modules and functions are named, never
    silently skipped."""
    old_root, new_root = pathlib.Path(old_dir), pathlib.Path(new_dir)
    old_files = {p.name: p for p in old_root.glob(pattern)
                if not p.name.startswith("__")}
    new_files = {p.name: p for p in new_root.glob(pattern)
                if not p.name.startswith("__")}
    common_modules = sorted(set(old_files) & set(new_files))
    added_modules = sorted(set(new_files) - set(old_files))
    removed_modules = sorted(set(old_files) - set(new_files))
    identical, changed, unknown = [], [], []
    added_fns, removed_fns = [], []
    for mod_name in common_modules:
        old_fns = _top_level_functions(old_files[mod_name])
        new_fns = _top_level_functions(new_files[mod_name])
        common_fns = sorted(set(old_fns) & set(new_fns))
        added_fns += [f"{mod_name}::{f}"
                     for f in sorted(set(new_fns) - set(old_fns))]
        removed_fns += [f"{mod_name}::{f}"
                        for f in sorted(set(old_fns) - set(new_fns))]
        for fn_name in common_fns:
            label = f"{mod_name}::{fn_name}"
            if old_fns[fn_name] == new_fns[fn_name]:
                identical.append(label) # textually identical: free win
                continue
            try:
                out = _verify_function_patch(old_fns[fn_name], new_fns[fn_name])
            except Exception as e:
                unknown.append({"function": label,
                                "reason": f"{type(e).__name__}: {e}"})
                continue
            if out["verified"]:
                identical.append(label)
            elif out["counterexample"] is not None:
                changed.append({"function": label,
                                "counterexample": out["counterexample"]})
            else:
                unknown.append({"function": label,
                                "reason": "outside the provable fragment "
                                          "(opaque constraints on every "
                                          "differing path)"})
    return {"functions_compared": len(identical) + len(changed) + len(unknown),
            "identical": identical, "changed": changed, "unknown": unknown,
            "added_modules": added_modules, "removed_modules": removed_modules,
            "added_functions": added_fns, "removed_functions": removed_fns}


def continuity_certificate(old_dir, new_dir, old_label="old",
                           new_label="new") -> dict:
    """The verdict over a whole snapshot comparison:
      'continuous' -- every common function verified behaviorally identical
      'evolved'    -- some functions changed, each with a named counterexample
                      (an expected, reviewable state for real development,
                      NOT itself a failure -- intentional changes do change
                      behavior; this names exactly what and where)
      'incomplete' -- some functions could not be compared at all (opaque
                      constraints or an extraction error); named, not hidden
    'incomplete' takes precedence in the status (an unreviewed function is
    a bigger gap than a reviewed, named change)."""
    report = compare_snapshots(old_dir, new_dir)
    if report["unknown"]:
        status = "incomplete"
    elif report["changed"]:
        status = "evolved"
    else:
        status = "continuous"
    return {"status": status, "old": old_label, "new": new_label, **report}


def render_report(cert: dict) -> str:
    """Markdown summary -- the self-hosting proof's sibling: not "the
    engine audited itself", but "the engine audited its own evolution"."""
    lines = [f"# Continuity report: {cert['old']} -> {cert['new']}", "",
            f"- status: **{cert['status']}**",
            f"- functions compared: {cert['functions_compared']}",
            f"- behaviorally identical: {len(cert['identical'])}",
            f"- changed (named, with witness): {len(cert['changed'])}",
            f"- incomplete (opaque/error): {len(cert['unknown'])}",
            f"- added modules: {len(cert['added_modules'])}  "
            f"removed modules: {len(cert['removed_modules'])}",
            f"- added functions: {len(cert['added_functions'])}  "
            f"removed functions: {len(cert['removed_functions'])}",
            ""]
    for c in cert["changed"]:
        ce = c["counterexample"]
        lines.append(f"## {c['function']}")
        if ce:
            lines.append(f"- distinguishing input: `{ce['inputs']}`")
            lines.append(f"- new-version path result: `{ce['result']}`")
            lines.append(f"- only reachable in: `{ce['only_in']}`")
        lines.append("")
    for u in cert["unknown"]:
        lines.append(f"## {u['function']} (incomplete)")
        lines.append(f"- {u['reason']}")
        lines.append("")
    return "\n".join(lines)
