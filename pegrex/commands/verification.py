"""PegRex verification command handlers."""
from __future__ import annotations

import json
import pathlib
import sys

from .common import ROOT, _emit_json, _expand


def _cmd_verify(a) -> int:
    import pipeline as pl
    pl.run_spec(a.spec)
    return 0


def _cmd_certs(a) -> int:
    import os as _os
    import subprocess as sp
    from concurrent.futures import ThreadPoolExecutor
    files = sorted((ROOT / "certs").glob("m*_*.py"))

    def run_one(m):
        """run one(m): see module docstring."""
        r = sp.run([sys.executable, str(m)], cwd=ROOT, capture_output=True)
        return r.returncode == 0

    # certs marked "# pegrex:serial" mutate the tree or spawn subprocess
    # run in a serial pre-phase; everything else runs in the parallel pool
    serial = [m for m in files if "# pegrex:serial" in m.read_text(encoding="utf-8")]
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


def _cmd_soundness(a) -> int:
    from ..core import get_engine
    result = get_engine().soundness(a.language)
    print(json.dumps(result.data, indent=1, sort_keys=True))
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
    tree = _ast.parse(open(args.file, encoding="utf-8").read())
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
        contracts = parse_contracts(open(args.file, encoding="utf-8").read())
    _emit_json(discharge_source(args.file, contracts))


def _cmd_mine(args):
    from pegrex.specmine import mine
    _emit_json(mine(args.file))


def _cmd_concolic(args):
    import importlib.util
    import tempfile, os
    src = open(args.file, encoding="utf-8").read()
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
    obj = _json.loads(open(args.result, encoding="utf-8").read()) if args.result else None
    _emit_json(wrap(obj))


def _cmd_zk(args):
    from pegrex.zk import audit_circuit
    _emit_json(audit_circuit(open(args.file, encoding="utf-8").read()))


def _cmd_harness_check(args):
    import json as _json
    from pegrex.harness import check_plan
    plan = _json.loads(open(args.plan, encoding="utf-8").read())
    _emit_json(check_plan(plan))


def _cmd_mlcheck(args):
    import json as _json
    from pegrex.mlgraph import check_equivalence
    spec = _json.load(open(args.spec, encoding="utf-8"))
    _emit_json(check_equivalence(spec["float"], spec["quant"],
                                 spec["samples"], spec["quantized"],
                                 spec["eps"]))


def _cmd_twin(args):
    from pegrex.twin import ask, build
    _emit_json(ask(build(args.root), args.question))


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
        _emit_json(verify(_json.load(open(args.verify, encoding="utf-8")), args.key))
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


def _cmd_roundtrip(args):
    from pegrex.py2cobol import round_trip
    out = round_trip(args.file)
    if args.print_cobol:
        print(out["cobol"], end="")
        out = {k: v for k, v in out.items() if k != "cobol"}
    _emit_json(out)


def _cmd_legal_ci(args):
    from pegrex.legalci import ci_report
    _emit_json(ci_report(open(args.file, encoding="utf-8").read(), warn_days=args.warn_days))


def _cmd_ic3(args):
    from pegrex.ic3 import prove
    from pegrex.ir import lower_condition
    from pegrex.linsolve import atoms_of
    init = []
    for a in args.init:
        init += atoms_of(lower_condition(a))
    _emit_json(prove(init, args.trans, args.prop, max_frames=args.frames))


def _cmd_insure(args):
    from pegrex.insure import quote, verify_quote
    q = quote(open(args.file, encoding="utf-8").read(), key=args.key, type_bits=args.bits)
    if args.verify:
        _emit_json({"ok": verify_quote(q, args.key)})
    else:
        _emit_json(q)
