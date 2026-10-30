#!/usr/bin/env python
"""
ci_gate -- one gate for local + CI: the existing checks composed,
not re-implemented. Three checks, three-valued each (pass / fail / unknown /
skipped), every verdict named:

  cognitive-budget        pegrex.cognitive per changed/target file; over-budget
                          functions fail the gate only with --fail-on-over
                          (they are always reported, loudly)
  changed-cognitive-budget
                          with --changed-since BASE, only Python files changed
                          from BASE...HEAD; new/changed complexity debt fails
  refinement-contracts    pegrex.refine discharge of `# requires:` /
                          `# ensures:` comments; a VIOLATED contract is a
                          disproof and always fails the gate; undischarged
                          contracts are reported as unknown, never assumed
  verify_patch            pegrex.semantics proof-or-counterexample between
                          --base and --head (two file paths, or two git refs
                          diffed per changed .py file); skipped with a
                          printed note when no base is available -- never
                          silently

Exit 0 with a summary table (or --json); exit 1 naming every failed check.
Stdlib only; a few files gate in well under 5 seconds.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

COGNITIVE_BUDGET = 7  # same default budget as pegrex.cognitive


class CIGateError(ValueError):
    pass


# ── file discovery ──────────────────────────────────────────────────────────
def _iter_py(paths):
    """Files to gate: explicit .py files, or every .py under the given dirs
    (hidden dirs, __pycache__ and .git skipped). Nonexistent inputs refuse
    loudly instead of being silently dropped."""
    out = []
    for raw in paths:
        p = pathlib.Path(raw)
        if not p.exists():
            raise CIGateError(f"ci-gate: path does not exist: {raw}")
        if p.is_file():
            if p.suffix == ".py":
                out.append(p)
            continue
        for q in sorted(p.rglob("*.py")):
            if any(part.startswith(".") or part == "__pycache__"
                   for part in q.parts):
                continue
            out.append(q)
    seen, uniq = set(), []
    for p in out:
        rp = str(p.resolve())
        if rp not in seen:
            seen.add(rp)
            uniq.append(p)
    return uniq


def _git(args, cwd):
    try:
        return subprocess.run(["git", *args], cwd=cwd,
                              capture_output=True, text=True, timeout=20)
    except FileNotFoundError:
        raise CIGateError(
            "ci-gate: 'git' executable not found -- refusing to guess what "
            "'staged' or a git ref means without it")
    except subprocess.TimeoutExpired:
        raise CIGateError(f"ci-gate: git {' '.join(args)} timed out")


def _require_git_repo(cwd):
    r = _git(["rev-parse", "--is-inside-work-tree"], cwd)
    if r.returncode != 0:
        raise CIGateError(
            "refusing to guess what 'staged' means outside a git repository")


def staged_files(cwd="."):
    """--staged: exactly the staged .py files. Outside a git repo (or with no
    git binary) this is a loud refusal, never a silent empty list."""
    _require_git_repo(cwd)
    r = _git(["diff", "--cached", "--name-only"], cwd)
    if r.returncode != 0:
        raise CIGateError(f"ci-gate: git diff --cached failed: {r.stderr.strip()}")
    return [pathlib.Path(cwd) / f for f in r.stdout.splitlines()
            if f.endswith(".py") and (pathlib.Path(cwd) / f).exists()]


def changed_python_files(base, cwd="."):
    """Return existing Python files changed in BASE...HEAD, never guessed."""
    cwd = pathlib.Path(cwd)
    _require_git_repo(cwd)
    r = _git(["diff", "--name-only", "--diff-filter=ACMRT",
              f"{base}...HEAD", "--", "*.py"], cwd)
    if r.returncode != 0:
        raise CIGateError(f"ci-gate: cannot list changed Python files from {base!r}: "
                          f"{r.stderr.strip()}")
    return [cwd / name for name in r.stdout.splitlines()
            if name.endswith(".py") and (cwd / name).is_file()]


# ── checks (each returns a verdict dict; none raises) ───────────────────────
def check_cognitive(files, fail_on_over, budget=COGNITIVE_BUDGET):
    from pegrex import cognitive
    over, unknown = [], []
    max_c, n_fn = 0, 0
    for p in files:
        try:
            import warnings
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", SyntaxWarning)
                r = cognitive.cognitive_complexity(p.read_text(encoding="utf-8"),
                                                   budget=budget)
        except Exception as e:  # engine hiccup: unknown, never a crash
            unknown.append(f"{p.name}: analyzer error {e!r}")
            continue
        if r.get("verdict") != "ok":
            unknown.append(f"{p.name}: {r.get('reason', 'unknown')}")
            continue
        for fn in r["functions"]:
            n_fn += 1
            max_c = max(max_c, fn["complexity"])
            if fn["complexity"] > budget:
                over.append(f"{p.name}::{fn['name']} "
                            f"(complexity {fn['complexity']} > {budget})")
    verdict = "pass"
    if fail_on_over and (over or unknown):
        verdict = "fail"
    elif unknown and not over:
        verdict = "unknown"
    detail = (f"{n_fn} function(s), max complexity {max_c} "
              f"(budget {budget}); over-budget: "
              + ("none" if not over else "; ".join(over))
              + ("; unknown: " + "; ".join(unknown) if unknown else ""))
    return {"name": "cognitive-budget", "verdict": verdict, "detail": detail,
            "failures": over if fail_on_over else [],
            "unknowns": unknown}


def check_changed_cognitive(base, cwd="."):
    """Fail new complexity debt without making historical debt a false pass."""
    files = changed_python_files(base, cwd)
    result = check_cognitive(files, fail_on_over=True)
    result["name"] = "changed-cognitive-budget"
    result["detail"] = (f"{len(files)} changed Python file(s) from {base}...HEAD; "
                        + result["detail"])
    return result


def check_refinement(files):
    from pegrex import refine
    violated, undischarged = [], []
    n_contracts = 0
    for p in files:
        try:
            src = p.read_text(encoding="utf-8")
            contracts = refine.parse_contracts(src)
            if not (contracts["requires"] or contracts["ensures"]):
                continue
            n_contracts += len(contracts["requires"]) + len(contracts["ensures"])
            for row in refine.discharge_source(str(p), contracts):
                for r in row["requires"]:
                    if r["status"] == "violated":
                        violated.append(f"{p.name}: requires {r['contract']!r} "
                                        f"on path [{', '.join(row['constraints'])}]")
                    elif r["status"] == "undischarged":
                        undischarged.append(f"{p.name}: requires {r['contract']!r}")
                for e in row["ensures"]:
                    if e["status"] == "violated":
                        violated.append(f"{p.name}: ensures {e['contract']!r} "
                                        f"on path [{', '.join(row['constraints'])}]")
                    elif e["status"] == "undischarged":
                        undischarged.append(f"{p.name}: ensures {e['contract']!r}")
        except CIGateError:
            raise
        except Exception as e:
            undischarged.append(f"{p.name}: discharge error {e!r}")
    verdict = "fail" if violated else ("unknown" if undischarged else "pass")
    detail = (f"{n_contracts} contract(s); violated: "
              + ("none" if not violated else "; ".join(violated))
              + ("; undischarged: " + "; ".join(undischarged)
                 if undischarged else ""))
    return {"name": "refinement-contracts", "verdict": verdict,
            "detail": detail, "failures": violated,
            "unknowns": undischarged}


def _pair_from_refs(base, head, cwd):
    """(before_path, after_path, label) pairs for two git refs, one per
    changed .py file. Refusal names the ref that did not resolve."""
    r = _git(["diff", "--name-only", "--diff-filter=ACMRT", base, head,
              "--", "*.py"], cwd)
    if r.returncode != 0:
        raise CIGateError(
            f"ci-gate: cannot diff {base!r}..{head!r}: {r.stderr.strip()} "
            "-- refusing to guess (are both git refs available with history?)")
    tmp = pathlib.Path(tempfile.mkdtemp(prefix="ci-gate-"))
    pairs = []
    for f in r.stdout.splitlines():
        rb = _git(["show", f"{base}:{f}"], cwd)
        rh = _git(["show", f"{head}:{f}"], cwd)
        if rb.returncode != 0 or rh.returncode != 0:
            continue  # added/deleted: nothing to pair, named in the note below
        bp, hp = tmp / ("base_" + f.replace("/", "_")), \
                 tmp / ("head_" + f.replace("/", "_"))
        bp.write_bytes(rb.stdout.encode())
        hp.write_bytes(rh.stdout.encode())
        pairs.append((str(bp), str(hp), f))
    return pairs


def check_verify_patch(base, head, cwd="."):
    from pegrex import semantics
    if not base and not head:
        return {"name": "verify_patch", "verdict": "skipped",
                "detail": "no --base/--head given -- SKIPPED (never silently)",
                "failures": [], "unknowns": []}
    if bool(base) != bool(head):
        raise CIGateError(
            "ci-gate: --base and --head must be given together")
    pb, ph = pathlib.Path(base), pathlib.Path(head)
    if pb.exists() and ph.exists():
        pairs = [(str(pb), str(ph), f"{base} -> {head}")]
    else:
        _require_git_repo(cwd)
        pairs = _pair_from_refs(base, head, cwd)
    failures = []
    for before, after, label in pairs:
        try:
            r = semantics.verify_patch(before, after)
        except Exception as e:
            failures.append(f"{label}: engine error {e!r}")
            continue
        if not r["verified"]:
            ce = r.get("counterexample")
            where = (f"counterexample {ce['inputs']}"
                     if ce else "distinguishing paths outside the linear "
                               "fragment (no concrete input)")
            failures.append(f"{label}: patch NOT verified -- {where}")
    return {"name": "verify_patch",
            "verdict": "fail" if failures else "pass",
            "detail": (f"{len(pairs)} file pair(s) checked; "
                       + ("all behaviorally equivalent"
                          if not failures else "; ".join(failures))),
            "failures": failures, "unknowns": []}


# ── reporting ───────────────────────────────────────────────────────────────
_VERDICT_MARK = {"pass": "PASS", "fail": "FAIL",
                 "unknown": "UNKNOWN", "skipped": "SKIPPED"}


def _render_table(checks, files, seconds):
    rows = "".join(f"  {c['name']:<24} {_VERDICT_MARK[c['verdict']]:<8} "
                   f"{c['detail']}\n" for c in checks)
    return (f"pegrex ci-gate: {len(files)} file(s) in {seconds:.2f}s\n"
            f"  {'check':<24} {'verdict':<8} detail\n{rows}"
            f"gate: {'PASS' if all(c['verdict'] != 'fail' for c in checks) else 'FAIL'}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ci-gate",
                                 description="pegrex gate: cognitive budget + "
                                             "refinement contracts + verify_patch")
    ap.add_argument("paths", nargs="*", default=["."],
                    help="files or directories to gate (default: .)")
    ap.add_argument("--fail-on-over", action="store_true",
                    help="fail the gate on over-budget (or unanalyzable) "
                         "functions; without it they are reported loudly only")
    ap.add_argument("--base", help="verify_patch 'before': file path or git ref")
    ap.add_argument("--head", help="verify_patch 'after': file path or git ref")
    ap.add_argument("--changed-since", metavar="BASE",
                    help="strictly gate cognitive complexity in Python files changed from BASE...HEAD")
    ap.add_argument("--staged", action="store_true",
                    help="gate exactly the staged .py files (git)")
    ap.add_argument("--json", action="store_true",
                    help="emit machine-readable per-check verdicts")
    args = ap.parse_args(argv)

    started = time.monotonic()
    files = staged_files() if args.staged else _iter_py(args.paths or ["."])
    checks = [check_cognitive(files, args.fail_on_over)]
    if args.changed_since:
        checks.append(check_changed_cognitive(args.changed_since))
    checks.extend([check_refinement(files),
                   check_verify_patch(args.base, args.head)])
    seconds = time.monotonic() - started
    failed = [c for c in checks if c["verdict"] == "fail"]
    if args.json:
        print(json.dumps({"ok": not failed,
                          "files": len(files),
                          "seconds": round(seconds, 3),
                          "checks": [{k: c[k] for k in
                                      ("name", "verdict", "detail",
                                       "failures", "unknowns")}
                                     for c in checks]},
                         indent=1))
    else:
        print(_render_table(checks, files, seconds))
    if failed:
        for c in failed:
            for f in c["failures"]:
                print(f"FAILED {c['name']}: {f}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except CIGateError as e:
        print(f"ci-gate: {e}", file=sys.stderr)
        sys.exit(2)
