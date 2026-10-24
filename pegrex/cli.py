"""
pegrex CLI

The complete command-line interface (argparse subcommands).
Every engine capability, one entry point: `pegrex <command> -h`"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

__version__ = "1.0.0"


def _expand(path: str, suffixes=(".py",)) -> list:
    """Expand a file or directory (recursive) to matching source files."""
    p = pathlib.Path(path)
    if p.is_dir():
        return sorted(f for f in p.rglob("*") if f.suffix in suffixes
                      and "__pycache__" not in str(f) and ".vendor" not in str(f))
    return [p]


def _cmd_audit(a) -> int:
    from tools.secaudit import audit
    if a.dir:
        import multiprocessing as mp
        from tools.secaudit import audit as _audit1
        with mp.Pool() as pool:
            results = pool.starmap(
                _audit1, [(str(f), None) for f in _expand(a.dir)])
        for f, fs in zip(_expand(a.dir), results):
            if fs:
                print(f"{f}:")
                for x in fs[:5]:
                    print(f"   {x['severity']:9} {x['id']} L{x['line']}")
        total = sum(len(fs) for fs in results)
        print(f"total: {total} findings across {len(results)} files")
        return 0
    findings = audit(a.file, a.lang)
    import json as _json, pathlib as _pl, datetime
    log = _pl.Path(".pegrex-cache/audit.log")
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a") as fh:
        fh.write(_json.dumps({"ts": datetime.datetime.now().isoformat(
            timespec="seconds"), "file": a.file,
            "findings": len(findings)}) + chr(10))
    if a.json:
        print(json.dumps({"file": a.file, "findings": findings,
                          "total": len(findings)}, indent=1))
    else:
        for f in findings:
            print(f"{f['severity']:9} {f.get('confidence', ''):7} "
                  f"{f['id']:44} L{f['line']:<4} {f['evidence']}")
        print()
        print(f"total: {len(findings)} findings")
    return 0


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
        g = CallGraph()
        for f in _expand(target):
            sub = build_call_graph(f.read_text(), a.lang)
            g.functions.update({f"{f.stem}.{k}": v
                                for k, v in sub.functions.items()})
            g.edges |= {(f"{f.stem}.{c}", f"{f.stem}.{d}")
                        for c, d in sub.edges}
    else:
        g = build_call_graph(pathlib.Path(a.file).read_text(), a.lang)
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
    for t in api.synthesize(a.source, a.lcov):
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
        b.check(str(f), f.read_text())
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
                {"bundles": bundles}, indent=1))
        return 0
    b = api.bundle(a.source or a.dir if isinstance(a.dir, str) else a.source, out=a.out)
    print(f"bundle: {len(b['paths'])} paths, sha {b['source_sha256'][:12]}")
    return 0


def _cmd_lint(a) -> int:
    sys.argv = ["grammar_lint", *a.grammars]
    from tools import grammar_lint
    return grammar_lint.main(sys.argv)


def _cmd_extract(a) -> int:
    sys.argv = ["extract_grammar", a.upstream, a.out]
    from tools import extract_grammar
    return extract_grammar.main(sys.argv)


def _cmd_health(a) -> int:
    from pegrex import api
    spec = api.spec(a.path, pathlib.Path(a.path).stem + "_health",
                    out_dir="specs")
    print(f"wrote specs/{pathlib.Path(a.path).stem}_health.spec.json: "
          f"{len(spec['tasks'])} tasks")
    return 0


def _cmd_verify(a) -> int:
    import pipeline as pl
    pl.run_spec(a.spec)
    return 0


def _cmd_certs(a) -> int:
    import os as _os
    import subprocess as sp
    from concurrent.futures import ThreadPoolExecutor
    files = sorted((ROOT / "certs").glob("m*_*.py")) + [ROOT / "certs/demo.py"]

    def run_one(m):
        """run one(m): see module docstring."""
        r = sp.run([sys.executable, str(m)], cwd=ROOT, capture_output=True)
        return r.returncode == 0

    # certs marked "# pegrex:serial" mutate the tree or spawn subprocess
    # run in a serial pre-phase; everything else runs in the parallel pool
    serial = [m for m in files if "# pegrex:serial" in m.read_text()]
    parallel = [m for m in files if m not in serial]

    ok = True
    results = {}
    for m in serial: # serial pre-phase
        results[m.name] = run_one(m)
    with ThreadPoolExecutor(max_workers=max(1, _os.cpu_count() or 4)) as pool:
        futures = {m.name: pool.submit(run_one, m) for m in parallel}
        for m in parallel:
            results[m.name] = futures[m.name].result()
    for m in files:
        passed = results[m.name]
        ok &= passed
        print(f"  {m.name:28} {'OK' if passed else 'FAIL'}")
    for spec in ("fact", "chain", "absval"):
        r = sp.run([sys.executable, "pipeline.py", f"specs/{spec}.json"],
                   cwd=ROOT, capture_output=True)
        ok &= r.returncode == 0
    r = sp.run([sys.executable, "pipeline.py", "specs/fact_negative.json"],
               cwd=ROOT, capture_output=True)
    ok &= r.returncode != 0
    print("CERTS:", "ALL GREEN" if ok else "FAILURES")
    return 0 if ok else 1


def _cmd_rules(a) -> int:
    cat = json.loads((ROOT / "pegrex/secrules.json").read_text())
    tc = json.loads((ROOT / "pegrex/secrules_taint.json").read_text())
    if a.json:
        print(json.dumps({"pattern_rules": len(cat["rules"]),
                          "taint_rules": len(tc["rules"])}, indent=1))
    else:
        langs = {}
        for r in cat["rules"]:
            for l in r.get("langs", ["any"]):
                langs[l] = langs.get(l, 0) + 1
        print(f"pattern rules: {len(cat['rules'])}")
        print(f"taint rules:   {len(tc['rules'])}")
        print("by language:", dict(sorted(langs.items(),
                                          key=lambda kv: -kv[1])[:10]))
    return 0


def _cmd_serve(a) -> int:
    import runpy
    runpy.run_path(str(ROOT / "service.py"), run_name="__main__")
    return 0


def _cmd_acp(a) -> int:
    import runpy
    sys.argv = ["acp", a.root]
    runpy.run_module("pegrex.acp", run_name="__main__")
    return 0


def _cmd_mcp(a) -> int:
    from pegrex.mcp import MCPServer
    return MCPServer().serve()


def _cmd_induce(a) -> int:
    """FULL grammar induction: examples in, grammar out (written to --out)."""
    from pegrex.induce import induce
    pos = [l for l in pathlib.Path(a.positives).read_text().splitlines()
           if l.strip()]
    neg = [l for l in pathlib.Path(a.negatives).read_text().splitlines()
           if l.strip()] if a.negatives else []
    seed = pathlib.Path(a.seed).read_text() if a.seed \
        else "START <- .+\n"
    best, score = induce(pos, neg, seed, rounds=a.rounds)
    print(f"score: {score[0]}/{len(pos)} pos, {score[1]}/{len(neg)} neg")
    print(best)
    if a.out:
        pathlib.Path(a.out).write_text(best)
        print(f"wrote {a.out}")
    return 0


def _cmd_workrun(a) -> int:
    """FULL .work execution: run the agent, check its invariants."""
    import json as _json
    from pegrex.workexec import execute
    out = execute(a.work, a.target)
    print(_json.dumps(out, indent=1))
    return 0


def _cmd_metaengine(a) -> int:
    """FULL meta-engine: examples -> grammar -> tags -> rule skeletons."""
    from pegrex.metaengine import build_system
    pos = [l for l in pathlib.Path(a.positives).read_text().splitlines()
           if l.strip()]
    neg = [l for l in pathlib.Path(a.negatives).read_text().splitlines()
           if l.strip()] if a.negatives else []
    out = build_system(pos, neg, "START <- .+\n", domain=a.domain)
    print(json.dumps({k: out[k] for k in ("tags", "score")}, indent=1))
    print("rule skeletons:", len(out["rule_skeletons"]))
    if a.out:
        pathlib.Path(a.out).write_text(json.dumps(out, indent=1))
    return 0




def _cmd_ci(a) -> int:
    import json as _json
    from pegrex.ci import analyze_pipeline
    print(_json.dumps(analyze_pipeline(a.file), indent=1))
    return 0


def _cmd_osv(a) -> int:
    import json as _json
    from pegrex.sca import scan
    print(_json.dumps(scan(a.file), indent=1)[:3000])
    return 0


def _cmd_explain(a) -> int:
    from pegrex import api
    from pegrex.explain import explain
    contract = api.contracts(a.file, a.lang)
    print(explain(contract, pathlib.Path(a.file).stem))
    return 0


def _cmd_caps(a) -> int:
    import json as _json
    from pegrex.capabilities import infer_capabilities, to_sandbox_manifest
    caps = infer_capabilities(pathlib.Path(a.file).read_text())
    print(_json.dumps({"capabilities": caps,
                       "sandbox": to_sandbox_manifest(caps)}, indent=1))
    return 0


def _cmd_export(a) -> int:
    from tools.secaudit import audit as _audit
    from pegrex.export import export as _export
    findings = _audit(a.file)
    text = _export(findings, a.format, a.out, a.file)
    print(text[:3000] if text.strip() else
          f"{len(findings)} findings "
          f"(wrote {a.out})" if a.out else f"{len(findings)} findings")
    return 0


def _cmd_verify_patch(args):
    from pegrex.semantics import verify_patch
    _emit_json(verify_patch(args.before, args.after, args.claim))


def _cmd_diff(args):
    from pegrex.semantics import semantic_diff
    _emit_json(semantic_diff(args.a, args.b))


def _cmd_emit(args):
    from pegrex import api
    from pegrex.emitter import emit_python
    import ast as _ast
    tree = _ast.parse(open(args.file).read())
    fn = next(n for n in tree.body if isinstance(n, _ast.FunctionDef))
    params = [a.arg for a in fn.args.args]
    code = emit_python(fn.name, params, api.contracts(args.file))
    if args.run:
        print(code, end="")
    else:
        _emit_json({"function": fn.name, "code": code})


def _cmd_check(args):
    from pegrex.refine import discharge_source, parse_contracts
    contracts = {"requires": args.requires or [], "ensures": args.ensures or []}
    if args.requires is None and args.ensures is None:
        contracts = parse_contracts(open(args.file).read())
    _emit_json(discharge_source(args.file, contracts))


def _cmd_mine(args):
    from pegrex.specmine import mine
    _emit_json(mine(args.file))


def _cmd_nl(args):
    from pegrex.nlspec import check
    _emit_json(check(args.file, nl_text=args.text))


def _cmd_concolic(args):
    import importlib.util
    import tempfile, os
    src = open(args.file).read()
    ns = {}
    exec(src, ns)
    fn = ns[args.fn_name]
    from pegrex.concolic import flip_and_verify, trace_fn
    run = trace_fn(fn, *args.args, source=src)
    out = {"result": run["result"], "branches": run["branches"],
           "opaque_branches": run["opaque_branches"]}
    if args.flip is not None:
        out["flip"] = flip_and_verify(fn, run, args.flip, source=src)
    _emit_json(out)


def _cmd_rank(args):
    from pegrex.rank import deltas_of, find_ranking
    deltas = {}
    for d in args.delta:
        k, v = d.split("=")
        deltas[k] = int(v)
    _emit_json({"guard": args.guard, "deltas": deltas,
                "ranking": find_ranking(args.guard, deltas)})


def _cmd_bench(args):
    from pegrex.benchmark import run_benchmark
    out = run_benchmark()
    for r in out.pop("results"):
        print(f"  {r['name']:<22} verified={r['verified']} expected={r['expected']}")
    _emit_json(out)


def _cmd_compress(args):
    from pegrex.compress import compress_context, validate_compression
    _emit_json({"context": compress_context(args.file),
                "validation": validate_compression(args.file)})


def _cmd_strategy(args):
    from pegrex import api
    from pegrex.linsolve import LinearBackend, atoms_of, parse_atom
    from pegrex.refine import _norm_constraint
    from pegrex.strategies import emit_hypothesis, sample_models, strategy
    lb = LinearBackend()
    rows = []
    for cs, res in api.contracts(args.file):
        atoms = []
        for c in cs:
            n = _norm_constraint(str(c))
            try:
                parse_atom(n)
                atoms.append(n)
            except Exception:
                pass
        rows.append({"path": sorted(map(str, cs)), "result": str(res),
                     "strategy": strategy(atoms, lb),
                     "models": sample_models(atoms, lb=lb)})
    for r in rows:
        st = r["strategy"]
        if st.get("integers"):
            print(emit_hypothesis(st, args.fn_name or "target"))
            print()
        _emit_json({k: v for k, v in r.items() if k != "strategy"})


def _cmd_modernize(args):
    from pegrex.modernize import modernize
    _emit_json(modernize(args.file, target=args.target))


def _cmd_tv(args):
    import json as _json
    from pegrex.tv import wrap
    obj = _json.loads(open(args.result).read()) if args.result else None
    _emit_json(wrap(obj))


def _cmd_zk(args):
    from pegrex.zk import audit_circuit
    _emit_json(audit_circuit(open(args.file).read()))


def _cmd_iac(args):
    from pegrex.iac import audit_policy, audit_terraform, can
    if args.file.endswith(".json"):
        _emit_json({"findings": audit_policy(open(args.file).read())})
    elif args.question:
        import json as _json
        doc = _json.load(open(args.policy)) if args.policy else {}
        action, _, resource = args.question.partition(" on ")
        _emit_json({"decision": can(doc.get("Statement", []), action, resource)})
    else:
        _emit_json({"findings": audit_terraform(open(args.file).read())})


def _cmd_harness_check(args):
    import json as _json
    from pegrex.harness import check_plan
    plan = _json.loads(open(args.plan).read())
    _emit_json(check_plan(plan))


def _cmd_bounty(args):
    from pegrex.bounty import run
    _emit_json(run(open(args.file).read(), args.sink))


def _cmd_compliance(args):
    from pegrex.compliance import audit_gdpr, audit_soc2
    out = {"gdpr": audit_gdpr(open(args.file).read())}
    if args.soc2:
        import json as _json
        out["soc2"] = audit_soc2(open(args.file).read(),
                                 _json.load(open(args.soc2)))
    _emit_json(out)


def _cmd_mlcheck(args):
    import json as _json
    from pegrex.mlgraph import check_equivalence
    spec = _json.load(open(args.spec))
    _emit_json(check_equivalence(spec["float"], spec["quant"],
                                 spec["samples"], spec["quantized"],
                                 spec["eps"]))


def _cmd_twin(args):
    from pegrex.twin import ask, build
    _emit_json(ask(build(args.root), args.question))


def _cmd_probpath(args):
    import json as _json
    from pegrex import api
    from pegrex.probpath import fit, prioritize
    spec = _json.load(open(args.spec))
    fitted = fit(api.contracts(spec["file"]), map(set, spec["traces"]))
    _emit_json({"fitted": fitted, "priority": prioritize(fitted, spec.get("sinks", []))})


def _cmd_attest(args):
    from pegrex.slsa import attest, publish_sigstore, verify
    if args.publish:
        try:
            publish_sigstore({}, token=args.token)
        except Exception as e:
            _emit_json({"published": False, "reason": str(e)[:160]})
        return
    if args.verify:
        import json as _json
        _emit_json(verify(_json.load(open(args.verify)), args.key))
        return
    _emit_json(attest(args.builder, args.command, {},
                      args.materials.split(","), args.key))


def _cmd_vapi(args):
    from pegrex.vapi import LatencyTracker, verify_or_refuse
    tr = LatencyTracker()
    out = verify_or_refuse(args.before, args.after, args.deadline_ms,
                           tracker=tr)
    out["sla"] = {"calls": tr.calls, "avg_ms": tr.avg_ms,
                  "deadline_misses": tr.deadline_misses}
    _emit_json(out)


def _cmd_cognitive(args):
    from pegrex.cognitive import cognitive_complexity
    out = cognitive_complexity(open(args.file).read(), budget=args.budget)
    _emit_json(out)
    if getattr(args, "fail_on_over", False) and out.get("verdict") == "ok":
        over = [f["name"] for f in out["functions"]
                if f["complexity"] > args.budget]
        if over:
            print("over-budget:", ", ".join(over), file=sys.stderr)
            raise SystemExit(1)


def _cmd_audit_bounded(args):
    import threading
    import time as _time
    from . import api
    box = {}
    def target():
        """target(): see module docstring."""
        try:
            box["result"] = api.audit(args.file)
        except Exception as e:
            box["error"] = str(e)[:200]
    t0 = _time.perf_counter()
    th = threading.Thread(target=target, daemon=True)
    th.start()
    th.join(args.timeout_ms / 1000.0)
    ms = round((_time.perf_counter() - t0) * 1000.0, 2)
    if th.is_alive():
        _emit_json({"verdict": "unknown",
                    "reason": f"audit exceeded {args.timeout_ms}ms budget",
                    "latency_ms": ms})
        return
    if "error" in box:
        _emit_json({"verdict": "unknown", "reason": box["error"],
                    "latency_ms": ms})
        return
    _emit_json({"verdict": "ok", "findings": len(box["result"]),
                "latency_ms": ms})


def _cmd_compile_nl(args):
    from pegrex.antihalluc import compile_nl
    _emit_json(compile_nl(args.text, args.file))


def _cmd_autopwn(args):
    from pegrex.autopwn import autopwn
    _emit_json(autopwn(open(args.file).read(), args.sink,
                       lambda fb: open(args.patch).read(),
                       max_rounds=args.rounds))


def _cmd_probverify(args):
    import json as _json
    from pegrex import api
    from pegrex.priorverify import verify_under_budget
    spec = _json.load(open(args.spec))
    out = verify_under_budget(api.contracts(spec["file"]),
                              map(set, spec["traces"]),
                              lambda atoms: spec.get("verdicts", {}).get(
                                  " ".join(atoms), "unknown"),
                              args.deadline_ms)
    _emit_json(out)


def _cmd_roundtrip(args):
    from pegrex.py2cobol import round_trip
    out = round_trip(args.file)
    if args.print_cobol:
        print(out["cobol"], end="")
        out = {k: v for k, v in out.items() if k != "cobol"}
    _emit_json(out)


def _cmd_legal_ci(args):
    from pegrex.legalci import ci_report
    _emit_json(ci_report(open(args.file).read(), warn_days=args.warn_days))


def _cmd_orgtwin(args):
    from pegrex.orgtwin import org_report, who_is_at_risk, who_is_unknown
    rep = org_report(args.root, budget=args.budget)
    _emit_json({"at_risk": who_is_at_risk(rep), "unknown": who_is_unknown(rep),
                "teams": rep["teams"]})


def _cmd_selfhost(args):
    import subprocess as _sp
    import sys as _sys
    argv = [_sys.executable, str(pathlib.Path(__file__).resolve().parent.parent
                                  / "tools" / "selfhost.py")]
    if args.check:
        argv.append("--check")
    r = _sp.run(argv, capture_output=True, text=True)
    print(r.stdout, end="")
    if r.returncode and not args.check:
        print(r.stderr, file=sys.stderr)
    raise SystemExit(r.returncode)


def _cmd_rosetta(args):
    from pegrex.rosetta import equivalence
    _emit_json(equivalence(args.spec))


def _cmd_difforacle(args):
    from pegrex.difforacle import run, run_canary
    _emit_json(run_canary(cc=args.cc) if args.canary
               else run(seed=args.seed, n=args.n, cc=args.cc))


def _cmd_llmcegis(args):
    from pegrex.llmcegis import HTTProposer, repair
    proposer = (HTTProposer(endpoint=args.endpoint)
                if args.proposer == "http" else "templates")
    _emit_json(repair(open(args.file).read(), claim=args.claim,
                      proposer=proposer, max_rounds=args.rounds))


def _cmd_ic3(args):
    from pegrex.ic3 import prove
    from pegrex.ir import lower_condition
    from pegrex.linsolve import atoms_of
    init = []
    for a in args.init:
        init += atoms_of(lower_condition(a))
    _emit_json(prove(init, args.trans, args.prop, max_frames=args.frames))


def _cmd_golf(args):
    from pegrex.golfbench import golf
    _emit_json(golf(args.cert, args.baseline))


def _cmd_insure(args):
    from pegrex.insure import quote, verify_quote
    q = quote(open(args.file).read(), key=args.key, type_bits=args.bits)
    if args.verify:
        _emit_json({"ok": verify_quote(q, args.key)})
    else:
        _emit_json(q)


def _cmd_dispatch(mod, fn):
    def h(args):
        m = __import__("pegrex." + mod, fromlist=[fn])
        import inspect as _i
        f = getattr(m, fn)
        sig = _i.signature(f)
        kwargs = {}
        for p in sig.parameters.values():
            if p.name == "src" and hasattr(args, "file"):
                kwargs["src"] = open(args.file).read()
            elif hasattr(args, p.name):
                kwargs[p.name] = getattr(args, p.name)
        _emit_json(f(**kwargs))
    return h




def build_parser() -> argparse.ArgumentParser:
    """build parser(): see module docstring."""
    p = argparse.ArgumentParser(
        prog="pegrex",
        description="Self-contained symbolic-execution and syntactic-analysis "
                    "engine: source -> mathematical specifications for AI agents.",
        epilog="certificates: `pegrex certs` runs all 67 proofs. "
               "Each command accepts -h.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", metavar="<command>")

    sp = sub.add_parser("audit", help="security audit (patterns + taint + SCA)")
    sp.add_argument("file", nargs="?")
    sp.add_argument("--dir", nargs="?", const=True, default=False,
                    metavar="PATH", help="recurse a directory (parallel)")
    sp.add_argument("--lang")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=_cmd_audit)

    sp = sub.add_parser("spec", help="AI spec schema (multi-view)")
    sp.add_argument("source", nargs="?")
    sp.add_argument("--dir", nargs="?", const=True, default=False,
                    metavar="PATH", help="recurse a directory")
    sp.add_argument("name")
    sp.add_argument("--out", default="specs")
    sp.add_argument("--opus", help="comma list of perspectives")
    sp.add_argument("--analyzers", help="comma list of analyzers")
    sp.set_defaults(fn=_cmd_spec)

    sp = sub.add_parser("contracts", help="function contract (paths -> results)")
    sp.add_argument("file")
    sp.add_argument("--lang", default="python")
    sp.set_defaults(fn=_cmd_contracts)

    sp = sub.add_parser("callgraph", help="function-call graph (DOT/ASCII)")
    sp.add_argument("file", nargs="?")
    sp.add_argument("--dir", nargs="?", const=True, default=False,
                    metavar="PATH",
                    help="recurse a directory (positional or this path)")
    sp.add_argument("--lang", default="python")
    sp.add_argument("--ascii", action="store_true")
    sp.set_defaults(fn=_cmd_callgraph)

    sp = sub.add_parser("coverage", help="path coverage overlay + gaps")
    sp.add_argument("source", nargs="?")
    sp.add_argument("--dir", nargs="?", const=True, default=False,
                    metavar="PATH", help="recurse a directory")
    sp.add_argument("--lcov", required=True)
    sp.add_argument("--lang", default="python")
    sp.set_defaults(fn=_cmd_coverage)

    sp = sub.add_parser("gaps", help="coverage gaps with constraint context")
    sp.add_argument("source")
    sp.add_argument("--lcov", required=True)
    sp.add_argument("--lang", default="python")
    sp.set_defaults(fn=_cmd_gaps)

    sp = sub.add_parser("tests", help="synthesize tests from coverage gaps")
    sp.add_argument("source")
    sp.add_argument("--lcov", required=True)
    sp.set_defaults(fn=_cmd_tests)

    sp = sub.add_parser("budget", help="complexity budget gate (exit 1 on fail)")
    sp.add_argument("file", nargs="?")
    sp.add_argument("--dir", nargs="?", const=True, default=False,
                    metavar="PATH", help="recurse a directory")
    sp.add_argument("--max-loc", type=int, default=300)
    sp.add_argument("--max-function-lines", type=int, default=40)
    sp.set_defaults(fn=_cmd_budget)

    sp = sub.add_parser("index", help="repo arch index")
    sp.add_argument("dir")
    sp.add_argument("--out", default="repo.index.json")
    sp.set_defaults(fn=_cmd_index)

    sp = sub.add_parser("bundle", help="portable verification bundle")
    sp.add_argument("source", nargs="?")
    sp.add_argument("--dir", nargs="?", const=True, default=False,
                    metavar="PATH", help="recurse a directory")
    sp.add_argument("--out")
    sp.set_defaults(fn=_cmd_bundle)

    sp = sub.add_parser("rules", help="rule catalog summary")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=_cmd_rules)

    sp = sub.add_parser("lint", help="grammar lint")
    sp.add_argument("grammars", nargs="+")
    sp.set_defaults(fn=_cmd_lint)

    sp = sub.add_parser("extract", help="verbatim grammar extraction")
    sp.add_argument("upstream")
    sp.add_argument("out")
    sp.set_defaults(fn=_cmd_extract)

    sp = sub.add_parser("induce", help="grammar induction (examples -> grammar)")
    sp.add_argument("positives", help="file of positive example lines")
    sp.add_argument("--negatives", help="file of negative example lines")
    sp.add_argument("--seed", help="seed grammar file")
    sp.add_argument("--out", help="write induced grammar here")
    sp.add_argument("--rounds", type=int, default=60)
    sp.set_defaults(fn=_cmd_induce)

    sp = sub.add_parser("workrun", help="execute a .work agent")
    sp.add_argument("work")
    sp.add_argument("--target", help="source file the agent analyzes")
    sp.set_defaults(fn=_cmd_workrun)

    sp = sub.add_parser("metaengine",
                        help="examples -> grammar -> tags -> rule skeletons")
    sp.add_argument("positives")
    sp.add_argument("--negatives")
    sp.add_argument("--domain", default="custom")
    sp.add_argument("--out")
    sp.set_defaults(fn=_cmd_metaengine)

    sp = sub.add_parser("health", help="self code-health spec")
    sp.add_argument("path")
    sp.set_defaults(fn=_cmd_health)

    sp = sub.add_parser("verify", help="translation certificate")
    sp.add_argument("spec")
    sp.set_defaults(fn=_cmd_verify)

    sp = sub.add_parser("cisec", help="CI/CD pipeline security analysis")
    sp.add_argument("file")
    sp.set_defaults(fn=_cmd_ci)
    sp = sub.add_parser("osvscan", help="dependency vulnerability scan (OSV)")
    sp.add_argument("file")
    sp.set_defaults(fn=_cmd_osv)
    sp = sub.add_parser("export", help="export findings (json/csv/html)")
    sp.add_argument("file")
    sp.add_argument("--format", default="json",
                    choices=["json", "csv", "html", "sarif"])
    sp.add_argument("--out")
    sp.set_defaults(fn=_cmd_export)
    sp = sub.add_parser("explain", help="explain a function as math")
    sp.add_argument("file")
    sp.add_argument("--lang", default="python")
    sp.set_defaults(fn=_cmd_explain)
    sp = sub.add_parser("caps", help="infer capabilities + sandbox policy")
    sp.add_argument("file")
    sp.set_defaults(fn=_cmd_caps)
    sp = sub.add_parser("certs", help="run ALL certificates + negative control")
    sp.set_defaults(fn=_cmd_certs)

    sp = sub.add_parser("serve", help="JSON-lines service (stdio)")
    sp.set_defaults(fn=_cmd_serve)

    sp = sub.add_parser("acp", help="ACP server (Zed-compatible)")
    sp.add_argument("root", nargs="?", default=".")
    sp.set_defaults(fn=_cmd_acp)

    sp = sub.add_parser("mcp", help="MCP server (tools + resources + router)")
    sp.set_defaults(fn=_cmd_mcp)


    sp = sub.add_parser("verify-patch", help="proof or counterexample for two sources")
    sp.add_argument("before")
    sp.add_argument("after")
    sp.add_argument("--claim", default="equivalent")
    sp.set_defaults(fn=_cmd_verify_patch)

    sp = sub.add_parser("diff", help="semantic diff (path contracts, not lines)")
    sp.add_argument("a")
    sp.add_argument("b")
    sp.set_defaults(fn=_cmd_diff)

    sp = sub.add_parser("emit", help="emit executable code from the contract IR")
    sp.add_argument("file")
    sp.add_argument("--run", action="store_true", help="print raw code")
    sp.set_defaults(fn=_cmd_emit)

    sp = sub.add_parser("check", help="discharge refinement contracts (requires/ensures)")
    sp.add_argument("file")
    sp.add_argument("--requires", action="append")
    sp.add_argument("--ensures", action="append")
    sp.set_defaults(fn=_cmd_check)

    sp = sub.add_parser("mine", help="mine likely invariants from path contracts")
    sp.add_argument("file")
    sp.set_defaults(fn=_cmd_mine)

    sp = sub.add_parser("nl", help="check a natural-language claim against the contracts")
    sp.add_argument("file")
    sp.add_argument("text")
    sp.set_defaults(fn=_cmd_nl)

    sp = sub.add_parser("concolic", help="trace a run and flip a branch")
    sp.add_argument("file")
    sp.add_argument("--fn", dest="fn_name", required=True)
    sp.add_argument("--args", type=int, nargs="*", default=[])
    sp.add_argument("--flip", type=int)
    sp.set_defaults(fn=_cmd_concolic)

    sp = sub.add_parser("rank", help="find a termination ranking function")
    sp.add_argument("guard")
    sp.add_argument("--delta", action="append", default=[], metavar="VAR=INT")
    sp.set_defaults(fn=_cmd_rank)

    sp = sub.add_parser("bench", help="deterministic agent-edit benchmark")
    sp.set_defaults(fn=_cmd_bench)

    sp = sub.add_parser("compress", help="LLM context compression (contracts + findings)")
    sp.add_argument("file")
    sp.set_defaults(fn=_cmd_compress)

    sp = sub.add_parser("strategy", help="Hypothesis strategies from path constraints")
    sp.add_argument("file")
    sp.add_argument("--fn", dest="fn_name")
    sp.set_defaults(fn=_cmd_strategy)

    sp = sub.add_parser("a2a", help="serve the agent-to-agent JSON-lines endpoint")
    sp.set_defaults(fn=lambda args: __import__("pegrex.a2a", fromlist=["serve"]).serve(sys.stdin, sys.stdout))

    sp = sub.add_parser("lsp", help="serve the LSP endpoint (Content-Length framing)")
    sp.set_defaults(fn=lambda args: __import__("pegrex.lsp", fromlist=["serve"]).serve(sys.stdin, sys.stdout.buffer))


    sp = sub.add_parser("modernize", help="legacy (COBOL/Fortran) -> target with equivalence certificate")
    sp.add_argument("file")
    sp.add_argument("--target", default="python")
    sp.set_defaults(fn=_cmd_modernize)

    sp = sub.add_parser("tv", help="normalize a result JSON to three-valued verdict")
    sp.add_argument("result", nargs="?")
    sp.set_defaults(fn=_cmd_tv)

    sp = sub.add_parser("zk", help="audit a Circom circuit for under-constrained signals")
    sp.add_argument("file")
    sp.set_defaults(fn=_cmd_zk)

    sp = sub.add_parser("iac", help="IAM/Terraform policy audit (or 'ACTION on RESOURCE' via --policy)")
    sp.add_argument("file", nargs="?")
    sp.add_argument("--policy")
    sp.add_argument("--question")
    sp.set_defaults(fn=_cmd_iac)

    sp = sub.add_parser("harness-check", help="check an agent plan JSON against the safety policy")
    sp.add_argument("plan")
    sp.set_defaults(fn=_cmd_harness_check)

    sp = sub.add_parser("bounty", help="discover/solve/minimize a PoC for a sink")
    sp.add_argument("file")
    sp.add_argument("sink")
    sp.set_defaults(fn=_cmd_bounty)

    sp = sub.add_parser("compliance", help="GDPR data-flow + optional SOC2 control audit")
    sp.add_argument("file")
    sp.add_argument("--soc2")
    sp.set_defaults(fn=_cmd_compliance)

    sp = sub.add_parser("mlcheck", help="quant/prune equivalence from a JSON spec")
    sp.add_argument("spec")
    sp.set_defaults(fn=_cmd_mlcheck)

    sp = sub.add_parser("twin", help="ask the codebase twin a reachability question")
    sp.add_argument("root")
    sp.add_argument("question")
    sp.set_defaults(fn=_cmd_twin)

    sp = sub.add_parser("probpath", help="path frequencies + priorities from traces (JSON spec)")
    sp.add_argument("spec")
    sp.set_defaults(fn=_cmd_probpath)

    sp = sub.add_parser("attest", help="SLSA-style attest/verify/publish (sigstore refuses offline)")
    sp.add_argument("--builder", default="local")
    sp.add_argument("--command", default="")
    sp.add_argument("--materials", default="")
    sp.add_argument("--key", default="local-key")
    sp.add_argument("--verify")
    sp.add_argument("--publish", action="store_true")
    sp.add_argument("--token")
    sp.set_defaults(fn=_cmd_attest)

    sp = sub.add_parser("vapi", help="time-bounded verify-or-refuse with SLA tracking")
    sp.add_argument("before")
    sp.add_argument("after")
    sp.add_argument("deadline_ms", type=int)
    sp.set_defaults(fn=_cmd_vapi)


    sp = sub.add_parser("cognitive", help="cognitive complexity + refactor plans (complexipy-faithful)")
    sp.add_argument("file")
    sp.add_argument("--budget", type=int, default=7)
    sp.add_argument("--fail-on-over", action="store_true",
                    help="exit 1 when any function exceeds the budget (CI gate)")
    sp.set_defaults(fn=_cmd_cognitive)


    sp = sub.add_parser("audit-bounded", help="audit under a latency budget (unknown on overrun)")
    sp.add_argument("file")
    sp.add_argument("--timeout-ms", type=int, default=30000)
    sp.set_defaults(fn=_cmd_audit_bounded)


    sp = sub.add_parser("compile-nl", help="anti-hallucination compiler: NL -> code -> proof (or refusal)")
    sp.add_argument("text")
    sp.add_argument("file")
    sp.set_defaults(fn=_cmd_compile_nl)

    sp = sub.add_parser("autopwn", help="policy-gated discover/solve/repair loop")
    sp.add_argument("file")
    sp.add_argument("sink")
    sp.add_argument("--patch", required=True, help="proposed fix source file")
    sp.add_argument("--rounds", type=int, default=4)
    sp.set_defaults(fn=_cmd_autopwn)

    sp = sub.add_parser("probverify", help="verify under budget, hot paths first, coverage attached")
    sp.add_argument("spec", help="JSON: {file, traces, verdicts}")
    sp.add_argument("--deadline-ms", type=int, default=1000)
    sp.set_defaults(fn=_cmd_probverify)

    sp = sub.add_parser("roundtrip", help="Python -> COBOL round-trip with contract identity")
    sp.add_argument("file")
    sp.add_argument("--print-cobol", action="store_true")
    sp.set_defaults(fn=_cmd_roundtrip)

    sp = sub.add_parser("legal-ci", help="contract-deadline CI artifact")
    sp.add_argument("file")
    sp.add_argument("--warn-days", type=int, default=14)
    sp.set_defaults(fn=_cmd_legal_ci)

    sp = sub.add_parser("orgtwin", help="org report: teams x compliance x complexity")
    sp.add_argument("root")
    sp.add_argument("--budget", type=int, default=7)
    sp.set_defaults(fn=_cmd_orgtwin)


    sp = sub.add_parser("selfhost", help="regenerate (or --check) docs/SELF.md, the engine's self-audit")
    sp.add_argument("--check", action="store_true")
    sp.set_defaults(fn=_cmd_selfhost)

    sp = sub.add_parser("rosetta", help="N-way cross-language equivalence (semantic diff matrix)")
    sp.add_argument("spec", help="spec JSON: {name, variants: [{language, source} x N>=2]}")
    sp.set_defaults(fn=_cmd_rosetta)

    sp = sub.add_parser("difforacle", help="differential oracle: pegrex contracts vs cc-compiled binary")
    sp.add_argument("--seed", type=int, default=0)
    sp.add_argument("-n", type=int, default=20)
    sp.add_argument("--cc", default="cc")
    sp.add_argument("--canary", action="store_true", help="run the signed-overflow UB canary instead")
    sp.set_defaults(fn=_cmd_difforacle)

    sp = sub.add_parser("llmcegis", help="CEGIS repair: LLM/template proposers, FM rejecters")
    sp.add_argument("file", help="source to repair")
    sp.add_argument("--claim", default="equivalent")
    sp.add_argument("--proposer", default="templates", choices=["templates", "http"])
    sp.add_argument("--endpoint", help="HTTP proposer endpoint (or PEGREX_LLM_ENDPOINT)")
    sp.add_argument("--rounds", type=int, default=6)
    sp.set_defaults(fn=_cmd_llmcegis)


    sp = sub.add_parser("ic3", help="IC3-lite: prove/refute/unknown a linear safety property")
    sp.add_argument("--init", action="append", required=True)
    sp.add_argument("--trans", action="append", required=True)
    sp.add_argument("--prop", required=True)
    sp.add_argument("--frames", type=int, default=6)
    sp.set_defaults(fn=_cmd_ic3)

    sp = sub.add_parser("golf", help="performance-golf a cert fixture vs its baseline")
    sp.add_argument("cert")
    sp.add_argument("--baseline")
    sp.set_defaults(fn=_cmd_golf)

    sp = sub.add_parser("insure", help="quote/verify a Solidity overflow-risk premium")
    sp.add_argument("file")
    sp.add_argument("--key", default="local-key")
    sp.add_argument("--bits", type=int, default=256)
    sp.add_argument("--verify", action="store_true")
    sp.set_defaults(fn=_cmd_insure)

    return p


# --help catalog: one compact usage line per command

def _fmt_action(a):
    """Compact token for one argparse action: --flag <val>, <pos>, <pos>..."""
    mt = a.metavar or a.dest
    if isinstance(mt, tuple):
        mt = mt[0]
    if a.option_strings:
        flag = a.option_strings[0]
        if a.nargs == 0:
            return flag
        if a.nargs in ("*", "+"):
            return flag + " <" + str(mt) + ">..."
        if isinstance(a.nargs, int) and a.nargs > 1:
            return flag + " <" + str(mt) + ">x" + str(a.nargs)
        return flag + " <" + str(mt) + ">"
    if a.nargs in ("+", "*"):
        return "<" + str(mt) + ">..."
    if isinstance(a.nargs, int) and a.nargs > 1:
        return " ".join("<" + str(mt) + ">" for _ in range(a.nargs))
    return "<" + str(mt) + ">"




def _use_color() -> bool:
    """TTY-aware color: on for terminals unless NO_COLOR; force with
    PEGREX_COLOR=always/never."""
    import os as _os
    forced = _os.environ.get("PEGREX_COLOR", "")
    if forced.lower() == "always":
        return True
    if forced.lower() == "never" or "NO_COLOR" in _os.environ:
        return False
    try:
        return sys.stdout.isatty()
    except Exception:
        return False


_C = {"rst": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
      "cyan": "\033[36m", "yellow": "\033[33m", "green": "\033[32m",
      "magenta": "\033[35m", "blue": "\033[34m", "rule": "\033[90m"}


def _paint(color: str, text: str, on: bool) -> str:
    return (_C[color] + text + _C["rst"]) if on else text


def _fmt_action(a):
    """Compact token for one argparse action: --flag <v>, <pos>, <pos>..."""
    mt = a.metavar or a.dest
    if isinstance(mt, tuple):
        mt = mt[0]
    if a.option_strings:
        flag = a.option_strings[0]
        if a.nargs == 0:
            return flag
        if a.nargs in ("*", "+"):
            return flag + " <" + str(mt) + ">..."
        if isinstance(a.nargs, int) and a.nargs > 1:
            return flag + " <" + str(mt) + ">x" + str(a.nargs)
        return flag + " <" + str(mt) + ">"
    if a.nargs in ("+", "*"):
        return "<" + str(mt) + ">..."
    if isinstance(a.nargs, int) and a.nargs > 1:
        return " ".join("<" + str(mt) + ">" for _ in range(a.nargs))
    return "<" + str(mt) + ">"


_SECTIONS = [
    ("Analysis & Audit", ["audit", "audit-bounded", "contracts", "callgraph",
                           "coverage", "gaps", "cognitive", "diff", "compress",
                           "twin", "orgtwin"]),
    ("Verification & Proofs", ["verify", "verify-patch", "check", "certs",
                                  "rank", "ic3", "transpile", "roundtrip",
                                  "probverify"]),
    ("Repair & Synthesis", ["repair", "mine", "nl", "compile-nl", "modernize",
                              "cegis", "autopwn", "bounty", "strategy"]),
    ("Security & Compliance", ["harness-check", "zk", "iac", "compliance",
                                 "legal-ci", "insure", "golf", "attest",
                                 "osvscan", "cisec"]),
    ("Execution & Testing", ["concolic", "bench", "probpath", "testsynth",
                               "selfhost"]),
    ("Protocol Endpoints", ["a2a", "lsp", "acp", "mcp"]),
    ("Repo Tooling", ["index", "bundle", "rules", "lint", "extract", "induce",
                        "workrun", "metaengine", "health", "budget", "caps",
                        "explain", "export", "spec", "mlcheck", "tv"]),
]


def format_command_catalog(parser) -> str:
    """Segmented, colorful catalog: sections group related commands; each
    line is name: --flag <v> <pos>...  description, syntax-colored.
    Plain text on non-TTY (or NO_COLOR)."""
    import argparse as _ap
    on = _use_color()
    subs = next((a for a in parser._actions
                 if isinstance(a, _ap._SubParsersAction)), None)
    if subs is None:
        return parser.format_help()
    helps = {a.metavar: a.help for a in subs._choices_actions}

    def render(name: str) -> str:
        sub = subs.choices[name]
        flags, pos = [], []
        for a in sub._actions:
            if a.option_strings:
                if a.dest == "help":
                    continue
                flags.append(_paint("yellow", _fmt_action(a), on))
            else:
                pos.append(_paint("green", _fmt_action(a), on))
        parts = [_paint("bold", _paint("cyan", name + ":", on), on)]
        parts.extend(flags)
        parts.extend(pos)
        desc = (sub.description or helps.get(name) or "").strip()
        line = " ".join(parts)
        if desc:
            line += "  " + _paint("dim", desc, on)
        return line

    out = []
    out.append(_paint("bold", _paint("blue", "pegrex", on), on) + " " +
               _paint("dim", "command catalog", on))
    out.append(_paint("rule", "=" * 60, on))
    grouped, seen = [], set()
    for sec, members in _SECTIONS:
        present = [m for m in members if m in subs.choices]
        if not present:
            continue
        seen |= set(present)
        grouped.append((sec, present))
    other = [n for n in sorted(subs.choices) if n not in seen]
    if other:
        grouped.append(("Other commands", other))
    for sec, members in grouped:
        out.append("")
        head = _paint("bold", _paint("magenta", ">> " + sec, on), on)
        out.append(head + " " + _paint("dim", "(%d)" % len(members), on))
        out.append(_paint("rule", "-" * 60, on))
        out.extend("  " + render(m) for m in members)
    out.append("")
    out.append(_paint("dim", str(len(subs.choices)) + " commands - use "
                      "<command> --help for full details; "
                      "PEGREX_COLOR=always/never forces color", on))
    return chr(10).join(out)


def _emit_json(obj):
    import json as _json
    print(_json.dumps(obj, indent=1, default=str))



def main(argv=None) -> int:
    if argv is None:
        argv = sys.argv[1:]
    if any(a in ("-h", "--help") for a in argv):
        first = next((a for a in argv if not a.startswith("-")), None)
        if first is None:
            print(format_command_catalog(build_parser()))
            return 0
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "fn"):
        print(format_command_catalog(parser))
        return 0
    try:
        return args.fn(args)
    except KeyboardInterrupt:
        return 130
    except SystemExit as e:
        return e.code or 0


if __name__ == "__main__":
    sys.exit(main())
