"""PegRex tooling command handlers."""
from __future__ import annotations

import json
import pathlib
import sys

from .common import ROOT, _emit_json, _expand


def _cmd_lint(a) -> int:
    from tools import grammar_lint
    return grammar_lint.main(["grammar_lint", *a.grammars])


def _cmd_extract(a) -> int:
    from tools import extract_grammar
    return extract_grammar.main(["extract_grammar", a.upstream, a.out])


def _cmd_rules(a) -> int:
    from tools.secaudit import Auditor
    auditor = Auditor()
    pattern_rules = auditor.catalog._pack.rules
    taint_rules = auditor.taint_rules
    coverage = auditor.coverage(a.lang if hasattr(a, "lang") else None)
    if a.json:
        print(json.dumps({"pattern_rules": len(pattern_rules),
                          "taint_rules": len(taint_rules),
                          "coverage": coverage}, indent=1, sort_keys=True))
    else:
        langs = {}
        for r in pattern_rules:
            for l in r.get("langs", ["any"]):
                langs[l] = langs.get(l, 0) + 1
        print(f"pattern rules: {len(pattern_rules)}")
        print(f"taint rules:   {len(taint_rules)}")
        print("by language:", dict(sorted(langs.items(),
                                          key=lambda kv: -kv[1])[:10]))
        for kind, report in coverage.items():
            print(f"{kind} coverage: {report['active']} active, "
                  f"{report['duplicates_removed']} duplicates, "
                  f"{report['disabled']} disabled, {report['inapplicable']} inapplicable")
    return 0


def _cmd_serve(a) -> int:
    import runpy
    runpy.run_path(str(ROOT / "service.py"), run_name="__main__")
    return 0


def _cmd_acp(a) -> int:
    import runpy
    previous_argv = sys.argv
    try:
        sys.argv = ["acp", a.root]
        runpy.run_module("pegrex.acp", run_name="__main__")
    finally:
        sys.argv = previous_argv
    return 0


def _cmd_mcp(a) -> int:
    from pegrex.mcp import MCPServer
    return MCPServer().serve()


def _cmd_induce(a) -> int:
    """FULL grammar induction: examples in, grammar out (written to --out)."""
    from pegrex.induce import induce
    pos = [l for l in pathlib.Path(a.positives).read_text(encoding="utf-8").splitlines()
           if l.strip()]
    neg = [l for l in pathlib.Path(a.negatives).read_text(encoding="utf-8").splitlines()
           if l.strip()] if a.negatives else []
    seed = pathlib.Path(a.seed).read_text(encoding="utf-8") if a.seed \
        else "START <- .+\n"
    best, score = induce(pos, neg, seed, rounds=a.rounds)
    print(f"score: {score[0]}/{len(pos)} pos, {score[1]}/{len(neg)} neg")
    print(best)
    if a.out:
        pathlib.Path(a.out).write_text(best, encoding="utf-8")
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
    pos = [l for l in pathlib.Path(a.positives).read_text(encoding="utf-8").splitlines()
           if l.strip()]
    neg = [l for l in pathlib.Path(a.negatives).read_text(encoding="utf-8").splitlines()
           if l.strip()] if a.negatives else []
    out = build_system(pos, neg, "START <- .+\n", domain=a.domain)
    print(json.dumps({k: out[k] for k in ("tags", "score")}, indent=1))
    print("rule skeletons:", len(out["rule_skeletons"]))
    if a.out:
        pathlib.Path(a.out).write_text(json.dumps(out, indent=1), encoding="utf-8")
    return 0


def _cmd_ci(a) -> int:
    import json as _json
    from pegrex.ci import analyze_pipeline
    print(_json.dumps(analyze_pipeline(a.file), indent=1))
    return 0


def _cmd_osv(a) -> int:
    import json as _json
    from pegrex.sca import scan
    report = scan(a.file, offline=a.offline, snapshot=a.osv_snapshot,
                  snapshot_out=a.snapshot_out)
    print(_json.dumps(report, indent=1))
    return 2 if a.fail_on_unknown and report["status"] == "unknown" else 0


def _cmd_explain(a) -> int:
    from pegrex import api
    from pegrex.explain import explain
    contract = api.contracts(a.file, a.lang)
    print(explain(contract, pathlib.Path(a.file).stem))
    return 0


def _cmd_caps(a) -> int:
    import json as _json
    from pegrex.capabilities import infer_capabilities, to_sandbox_manifest
    caps = infer_capabilities(pathlib.Path(a.file).read_text(encoding="utf-8"))
    print(_json.dumps({"capabilities": caps,
                       "sandbox": to_sandbox_manifest(caps)}, indent=1))
    return 0


def _cmd_export(a) -> int:
    from tools.secaudit import audit_report
    from pegrex.export import export as _export
    report = audit_report(a.file)
    findings = report["findings"]
    text = _export(findings, a.format, a.out, a.file,
                   provenance=report["provenance"])
    print(text[:3000] if text.strip() else
          f"{len(findings)} findings "
          f"(wrote {a.out})" if a.out else f"{len(findings)} findings")
    return 0


def _cmd_nl(args):
    from pegrex.nlspec import check
    _emit_json(check(args.file, nl_text=args.text))


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


def _cmd_iac(args):
    from pegrex.iac import audit_policy, audit_terraform, can
    if args.file.endswith(".json"):
        _emit_json({"findings": audit_policy(open(args.file, encoding="utf-8").read())})
    elif args.question:
        import json as _json
        doc = _json.load(open(args.policy, encoding="utf-8")) if args.policy else {}
        action, _, resource = args.question.partition(" on ")
        _emit_json({"decision": can(doc.get("Statement", []), action, resource)})
    else:
        _emit_json({"findings": audit_terraform(open(args.file, encoding="utf-8").read())})


def _cmd_bounty(args):
    from pegrex.bounty import run
    _emit_json(run(open(args.file, encoding="utf-8").read(), args.sink))


def _cmd_compliance(args):
    from pegrex.compliance import audit_gdpr, audit_soc2
    out = {"gdpr": audit_gdpr(open(args.file, encoding="utf-8").read())}
    if args.soc2:
        import json as _json
        out["soc2"] = audit_soc2(open(args.file, encoding="utf-8").read(),
                                 _json.load(open(args.soc2, encoding="utf-8")))
    _emit_json(out)


def _cmd_compile_nl(args):
    from pegrex.antihalluc import compile_nl
    _emit_json(compile_nl(args.text, args.file))


def _cmd_autopwn(args):
    from pegrex.autopwn import autopwn
    _emit_json(autopwn(open(args.file, encoding="utf-8").read(), args.sink,
                       lambda fb: open(args.patch, encoding="utf-8").read(),
                       max_rounds=args.rounds))


def _cmd_orgtwin(args):
    from pegrex.orgtwin import org_report, who_is_at_risk, who_is_unknown
    rep = org_report(args.root, budget=args.budget)
    _emit_json({"at_risk": who_is_at_risk(rep), "unknown": who_is_unknown(rep),
                "teams": rep["teams"]})


def _cmd_selfhost(args):
    """Run the repository/installed-tools self-audit generator by its real path."""
    import subprocess as _sp
    argv = [sys.executable, str(ROOT / "tools" / "selfhost.py")]
    if args.check:
        argv.append("--check")
    result = _sp.run(argv, capture_output=True, text=True, check=False)
    print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    raise SystemExit(result.returncode)


def _cmd_rosetta(args):
    from pegrex.rosetta import equivalence
    _emit_json(equivalence(args.spec))


def _cmd_llmcegis(args):
    from pegrex.llmcegis import HTTProposer, repair
    proposer = (HTTProposer(endpoint=args.endpoint)
                if args.proposer == "http" else "templates")
    _emit_json(repair(open(args.file, encoding="utf-8").read(), claim=args.claim,
                      proposer=proposer, max_rounds=args.rounds))


def _cmd_golf(args):
    from pegrex.golfbench import golf
    _emit_json(golf(args.cert, args.baseline))
