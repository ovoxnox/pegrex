"Built-in opus: perspectives that turn findings into agent tasks."
from ..core import opus

SEV2PRIO = {"CRITICAL": "P0", "HIGH": "P1", "MEDIUM": "P2", "LOW": "P3", "INFO": "P4"}


@opus("security")
def security_view(ctx, facts):
    fs = [f for f in facts if f.analyzer == "security"]
    tasks = []
    seen = {}
    for f in fs:
        e = seen.setdefault(f.check_id, {"f": f, "lines": []})
        e["lines"].append(f.line)
    for cid, e in sorted(seen.items(),
                         key=lambda kv: {"CRITICAL": 0, "HIGH": 1}.get(kv[1]["f"].severity, 9)):
        f = e["f"]
        tasks.append({
            "priority": SEV2PRIO.get(f.severity, "P3"),
            "severity": f.severity,
            "title": "[%s] %s" % (cid, f.fix or (f.evidence[:110]
                             if cid == "analyzer-error"
                             else "investigate")),
            "lines": sorted(set(e["lines"])),
            "acceptance_criteria": [
                "the flagged pattern no longer matches %s" % cid,
                "no regression in surrounding behavior"],
            "verify": ["python tools/secaudit.py %s | %s count == 0"
                       % (ctx.path, cid)],
            "estimate": "S" if f.severity in ("LOW", "MEDIUM") else "M",
            "risk": "medium" if f.severity in ("CRITICAL", "HIGH") else "low",
            "depends_on": [],
        })
    return {"summary": "%d security finding(s)" % len(fs), "tasks": tasks}


@opus("refactor")
def refactor_view(ctx, facts):
    fs = [f for f in facts if f.analyzer in ("quality", "structure")
          and f.severity in ("HIGH", "MEDIUM")]
    tasks = []
    for f in fs[:12]:
        tasks.append({
            "priority": SEV2PRIO.get(f.severity, "P3"),
            "severity": f.severity,
            "title": "[%s] %s" % (f.check_id, f.fix or f.evidence),
            "lines": [f.line],
            "acceptance_criteria": ["smell eliminated",
                                    "function behavior unchanged"],
            "verify": ["python -m py_compile %s" % ctx.path,
                       "tests still pass"],
            "estimate": "S",
            "risk": "low",
            "depends_on": [],
        })
    fm = next((f for f in facts if f.check_id == "file-metrics"), None)
    summary = "%d maintainability finding(s)" % len(fs)
    if fm:
        summary += "; " + fm.evidence
    return {"summary": summary, "tasks": tasks}


@opus("testing")
def testing_view(ctx, facts):
    fs = [f for f in facts if f.analyzer == "testing"]
    return {"summary": "%d function(s) without tests" % len(fs),
            "tasks": [{
                "priority": "P2",
                "severity": f.severity,
                "title": "[%s] %s" % (f.check_id, f.fix),
                "lines": [f.line],
                "acceptance_criteria": [
                    "test_%s exists and passes" % f.symbol,
                    "covers at least one edge case"],
                "verify": ["python -m pytest test_%s.py -q" % f.symbol],
                "estimate": "M",
                "risk": "low",
                "depends_on": [],
            } for f in fs]}


@opus("documentation")
def documentation_view(ctx, facts):
    fs = [f for f in facts if f.analyzer == "documentation"]
    return {"summary": "%d public symbol(s) undocumented" % len(fs),
            "tasks": [{
                "priority": "P3",
                "severity": "LOW",
                "title": "Add docstrings to %d public symbols" % len(fs),
                "lines": sorted({f.line for f in fs}),
                "acceptance_criteria": [
                    "every public function/class has a docstring",
                    "docstrings follow project style"],
                "verify": ["pydocstyle %s --select=D103" % ctx.path],
                "estimate": "S",
                "risk": "low",
                "depends_on": []}]}


@opus("architecture")
def architecture_view(ctx, facts):
    fs = [f for f in facts if f.analyzer == "structure"]
    fns = [f for f in fs if f.check_id == "function"]
    fm = next((f for f in fs if f.check_id == "file-metrics"), None)
    tasks = []
    if fm and fm.metric.get("loc", 0) > 300:
        tasks.append({
            "priority": "P2",
            "severity": "MEDIUM",
            "title": "Split module: %d lines, %d functions" % (
                fm.metric["loc"], fm.metric["functions"]),
            "lines": [1],
            "acceptance_criteria": [
                "module split by responsibility (CLI / engine / output)",
                "public API preserved via re-exports",
                "each new module under 200 lines"],
            "verify": ["python -m py_compile on each new module",
                       "top-level import still works"],
            "estimate": "L",
            "risk": "medium",
            "depends_on": ["security tasks complete"],
        })
    hotspots = sorted(fns, key=lambda f: -f.metric.get("bytes", 0))[:3]
    if hotspots:
        tasks.append({
            "priority": "P3",
            "severity": "LOW",
            "title": "Extract helpers from largest functions: "
                     + ", ".join(h.symbol for h in hotspots),
            "lines": [h.line for h in hotspots],
            "acceptance_criteria": ["each extracted helper has one job"],
            "verify": ["tests pass", "function outputs identical"],
            "estimate": "M", "risk": "low", "depends_on": []})
    deps = next((f for f in facts if f.analyzer == "dependencies"), None)
    summary = "%d functions" % len(fns)
    if deps:
        summary += "; deps: " + deps.evidence
    return {"summary": summary, "tasks": tasks}
