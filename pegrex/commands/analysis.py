"""PegRex analysis command handlers."""
from __future__ import annotations

import json
import pathlib
import sys

from .common import ROOT, _emit_json, _expand


def _cmd_audit(a) -> int:
    from tools.secaudit import aggregate_scan_coverage, audit_report, gate_exit

    def emit(report, findings):
        """Implement emit with the module's explicit API and failure semantics."""
        if a.sarif:
            from pegrex.export import to_sarif
            text = to_sarif(findings, provenance=report.get("provenance"))
        elif a.json:
            if a.schema_envelope:
                from ..schema import cli_envelope
                report = cli_envelope("audit", report)
            text = json.dumps(report, indent=1)
        else:
            text = ""
            for finding in findings:
                suppressed = " SUPPRESSED" if finding.get("suppressed") else ""
                print(f"{finding['severity']:9} {finding.get('confidence', ''):7} "
                      f"{finding['id']:44} L{finding['line']:<4} "
                      f"{finding['evidence']}{suppressed}")
            print(f"\ntotal: {len(findings)} findings; "
                  f"active: {report['active_total']}")
        if text:
            print(text)
        if a.out:
            pathlib.Path(a.out).write_text(text or json.dumps(report, indent=1), encoding="utf-8")

    if a.dir:
        from ..languages import EXTENSION_MAP
        files = _expand(a.dir, suffixes=tuple(EXTENSION_MAP))
        # Each file is independently bounded when a mode is selected; sequential
        # orchestration avoids nested daemon-process pools and preserves order.
        reports = [audit_report(str(f), None, mode=getattr(a, "mode", None)) for f in files]
        findings = [finding for report in reports for finding in report["findings"]]
        report = {
            "schema": "pegrex.security-scan-set.v1",
            "files": [{"file": row["file"], "total": row["total"],
                       "provenance": row["provenance"]} for row in reports],
            "findings": findings, "total": len(findings),
            "active_total": sum(row["active_total"] for row in reports),
            "suppressed_total": sum(row["suppressed_total"] for row in reports),
            "coverage": aggregate_scan_coverage(reports),
            "provenance": {"schema": "pegrex.security-provenance-set.v1",
                           "sources": [row["provenance"] for row in reports]},
        }
        if not (a.json or a.sarif):
            for row in reports:
                if row["findings"]:
                    print(f"{row['file']}:")
                    for finding in row["findings"][:5]:
                        print(f"   {finding['severity']:9} {finding['id']} "
                              f"L{finding['line']}")
            print(f"total: {len(findings)} findings across {len(reports)} files")
            if a.out:
                pathlib.Path(a.out).write_text(json.dumps(report, indent=1), encoding="utf-8")
        else:
            emit(report, findings)
        return gate_exit(findings, a.fail_on, a.fail_on_unknown)

    report = audit_report(a.file, a.lang, mode=getattr(a, "mode", None))
    findings = report["findings"]
    import datetime
    log = pathlib.Path(".pegrex-cache/audit.log")
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": datetime.datetime.now().isoformat(
            timespec="seconds"), "file": a.file,
            "findings": len(findings)}) + chr(10))
    emit(report, findings)
    return gate_exit(findings, a.fail_on, a.fail_on_unknown)


def _cmd_spec(a) -> int:
    from pegrex import api
    if a.dir:
        for f in _expand(a.dir if isinstance(a.dir, str) else (a.source or ".")):
            spec = api.spec(str(f), f"{a.name}_{f.stem}", out_dir=a.out,
                            views=a.opus, analyzers=a.analyzers)
            print(f"  {f.name}: {len(spec['tasks'])} tasks")
        return 0
    spec = api.spec(a.source, a.name, out_dir=a.out, views=a.opus,
                    analyzers=a.analyzers)
    print(f"wrote {a.out}/{a.name}.spec.json "
          f"({len(spec['tasks'])} tasks, "
          f"{spec['meta']['finding_count']} findings)")
    return 0


def _cmd_contracts(a) -> int:
    from pegrex import api
    for cons, res in api.contracts(a.file, a.lang):
        print(f"  {sorted(cons)} -> {res}")
    return 0


def _cmd_callgraph(a) -> int:
    from pegrex.callgraph import CallGraph, build_call_graph
    target = a.dir if isinstance(a.dir, str) else (a.file or ".")
    if a.dir:
        from ..concurrency import benchmark_process_map, callgraph_worker, process_map
        g = CallGraph()
        files = _expand(target)
        tasks = [(str(f), a.lang) for f in files]
        if a.benchmark:
            report = benchmark_process_map(callgraph_worker, tasks, workers=a.jobs)
            print(json.dumps({"callgraph_benchmark": report}), file=sys.stderr)
        results = process_map(callgraph_worker, tasks, workers=a.jobs, min_parallel=1)
        for f, (_, sub) in zip(files, results):
            g.functions.update({f"{f.stem}.{k}": v
                                for k, v in sub.functions.items()})
            g.edges |= {(f"{f.stem}.{c}", f"{f.stem}.{d}")
                        for c, d in sub.edges}
    else:
        g = build_call_graph(pathlib.Path(a.file).read_text(encoding="utf-8"), a.lang)
    print(g.to_ascii() if a.ascii else g.to_dot())
    return 0


def _cmd_coverage(a) -> int:
    from pegrex import api
    if a.dir:
        rc = 0
        for f in _expand(a.dir if isinstance(a.dir, str) else (a.source or ".")):
            out = api.coverage(str(f), a.lcov, a.lang)
            gaps = [g for g in out["gaps"]]
            print(f"{f}: {len(out['paths'])} paths, {len(gaps)} gap(s)")
            rc |= bool(gaps)
        return rc
    out = api.coverage(a.source, a.lcov, a.lang)
    for p in out["paths"]:
        mark = "COVERED" if p["covered"] else "gap"
        print(f"  {mark:8} {p['blocks']}")
    for g in out["gaps"]:
        print(f"  gap: {sorted(set(g['constraints']))}")
    return 0


def _cmd_gaps(a) -> int:
    from pegrex import api
    for g in api.gaps(a.source, a.lcov, a.lang):
        print(f"  {sorted(set(g['constraints']))}")
    return 0


def _cmd_tests(a) -> int:
    from pegrex import api
    for t in api.synthesize_tests_from_coverage(a.source, a.lcov):
        print(t.test_body)
        print()
    return 0


def _cmd_budget(a) -> int:
    from pegrex.budget import Budget
    _t = a.dir if isinstance(a.dir, str) else (a.file or ".")
    files = _expand(_t) if a.dir else [pathlib.Path(a.file)]
    all_findings, failed = [], False
    for f in files:
        b = Budget(max_loc=a.max_loc,
                   max_function_lines=a.max_function_lines)
        b.check(str(f), f.read_text(encoding="utf-8"))
        all_findings += b.findings
        failed |= not b.passed
        if b.findings:
            print(f"{f}:")
            for x in b.findings:
                print("  ", x)
    print(f"gate: {'FAIL' if failed else 'PASS'} "
          f"({len(files)} files, {len(all_findings)} findings)")
    return 1 if failed else 0


def _cmd_index(a) -> int:
    from pegrex import api
    idx = api.repo_index(a.dir, out=a.out)
    print(f"wrote {a.out}: {len(idx['containers'])} containers")
    return 0


def _cmd_bundle(a) -> int:
    from pegrex import api
    if a.dir:
        import json as _json
        bundles = {}
        for f in _expand(a.dir if isinstance(a.dir, str) else (a.source or ".")):
            b = api.bundle(str(f))
            bundles[f.stem] = b
            print(f"  {f.name}: {len(b['paths'])} paths")
        if a.out:
            pathlib.Path(a.out).write_text(_json.dumps(
                {"bundles": bundles}, indent=1), encoding="utf-8")
        return 0
    b = api.bundle(a.source or a.dir if isinstance(a.dir, str) else a.source, out=a.out)
    print(f"bundle: {len(b['paths'])} paths, sha {b['source_sha256'][:12]}")
    return 0


def _cmd_health(a) -> int:
    from pegrex import api
    spec = api.spec(a.path, pathlib.Path(a.path).stem + "_health",
                    out_dir="specs")
    print(f"wrote specs/{pathlib.Path(a.path).stem}_health.spec.json: "
          f"{len(spec['tasks'])} tasks")
    return 0


def _cmd_probpath(args):
    import json as _json
    from pegrex import api
    from pegrex.probpath import fit, prioritize
    spec = _json.load(open(args.spec, encoding="utf-8"))
    fitted = fit(api.contracts(spec["file"]), map(set, spec["traces"]))
    _emit_json({"fitted": fitted, "priority": prioritize(fitted, spec.get("sinks", []))})


def _cmd_cognitive(args):
    from pegrex.cognitive import cognitive_complexity
    out = cognitive_complexity(open(args.file, encoding="utf-8").read(), budget=args.budget)
    _emit_json(out)
    if getattr(args, "fail_on_over", False) and out.get("verdict") == "ok":
        over = [f["name"] for f in out["functions"]
                if f["complexity"] > args.budget]
        if over:
            print("over-budget:", ", ".join(over), file=sys.stderr)
            raise SystemExit(1)


def _cmd_audit_bounded(args):
    import multiprocessing as mp
    import queue
    import time as _time
    t0 = _time.perf_counter()
    ctx = mp.get_context()
    output = ctx.Queue()
    process = ctx.Process(target=_audit_process, args=(args.file, output), daemon=False)
    process.start()
    process.join(args.timeout_ms / 1000.0)
    ms = round((_time.perf_counter() - t0) * 1000.0, 2)
    if process.is_alive():
        process.terminate()       # the deadline cancels the actual scan
        process.join(1)
        if process.is_alive() and hasattr(process, "kill"):
            process.kill()
            process.join()
        _emit_json({"verdict": "unknown",
                    "reason": f"audit exceeded {args.timeout_ms}ms budget",
                    "latency_ms": ms})
        return
    try:
        box = output.get(timeout=0.2)
    except queue.Empty:
        box = {"error": "audit worker returned no result"}
    finally:
        output.close()
    if "error" in box:
        _emit_json({"verdict": "unknown", "reason": box["error"],
                    "latency_ms": ms})
        return
    _emit_json({"verdict": "ok", "findings": len(box["result"]),
                "latency_ms": ms})


def _cmd_probverify(args):
    import json as _json
    from pegrex import api
    from pegrex.priorverify import verify_under_budget
    spec = _json.load(open(args.spec, encoding="utf-8"))
    out = verify_under_budget(api.contracts(spec["file"]),
                              map(set, spec["traces"]),
                              lambda atoms: spec.get("verdicts", {}).get(
                                  " ".join(atoms), "unknown"),
                              args.deadline_ms)
    _emit_json(out)


def _cmd_difforacle(args):
    from pegrex.difforacle import run, run_canary
    _emit_json(run_canary(cc=args.cc) if args.canary
               else run(seed=args.seed, n=args.n, cc=args.cc))
