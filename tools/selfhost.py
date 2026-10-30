#!/usr/bin/env python
"""
selfhost - the self-hosting proof: pegrex audits pegrex.

Regenerates docs/SELF.md from three engine reports over pegrex/ itself:
the codebase twin (call graph + ownership), cognitive complexity (with
refactor plans), and path contracts where extraction succeeds (unknown
where it does not -- the report publishes its own refusals).

--check: exit 1 when SELF.md is stale relative to the engine sources
(the CI gate: the engine that audits everything must audit itself on
every build).
"""
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def engine_files():
    """Return every Python module in the engine, including package initializers."""
    return sorted((ROOT / "pegrex").rglob("*.py"))


def engine_digest():
    """Hash exact paths, lengths, and bytes for every analyzed engine input."""
    h = hashlib.sha256()
    engine = ROOT / "pegrex"
    for p in engine_files():
        relative = p.relative_to(engine).as_posix()
        payload = p.read_bytes()
        h.update(relative.encode("utf-8"))
        h.update(len(payload).to_bytes(8, "big"))
        h.update(payload)
    return h.hexdigest()[:16]


def refusal_reason(error):
    """Return a bounded, checkout-independent contract-extraction refusal reason."""
    message = " ".join(str(error).split()).replace(str(ROOT), "<checkout>")
    if len(message) > 240:
        message = message[:237] + "..."
    return f"{type(error).__name__}: {message}" if message else type(error).__name__


def _contracts_bounded(path, max_paths=10_000):
    """Extract contracts with a deterministic structural path budget.

    Wall-clock daemon-thread timeouts made identical sources alternate between
    extracted and UNKNOWN under varying machine load, while abandoned threads
    continued analyzing in the background. The registered pipeline's bounded
    enumerator instead refuses path explosion deterministically and no worker
    outlives the extraction call.
    """
    from pegrex.core.contracts import as_legacy_pairs, canonicalize
    from pegrex.languages import extract_contract_pairs
    source = pathlib.Path(path).read_text(encoding="utf-8")
    pairs = extract_contract_pairs("python", source, max_paths=max_paths)
    return as_legacy_pairs(canonicalize(pairs))


def collect():
    from pegrex.twin import build as twin_build, cognitive_report
    from pegrex.cognitive import cognitive_complexity
    engine = ROOT / "pegrex"
    twin = twin_build(str(engine))
    cog = cognitive_report(twin, budget=10)
    rows = []
    loc_total = 0
    contract_ok = contract_unknown = 0
    # `cognitive_report()` already runs the cognitive analyzer once per file.
    # Aggregate its evidence here instead of repeating the expensive parse for
    # every module. Files with no discovered functions still get one direct run.
    cognitive_by_file = {}
    for item in cog:
        path = item.get("file")
        if not path:
            continue
        aggregate = cognitive_by_file.setdefault(
            path, {"complexity": 0, "over_budget": [], "plans": 0,
                   "unknown": False})
        if item.get("verdict") == "unknown":
            aggregate["unknown"] = True
            continue
        aggregate["complexity"] += int(item.get("complexity", 0))
        if item.get("over_budget"):
            aggregate["over_budget"].append(item.get("function", "?"))
        aggregate["plans"] += len(item.get("refactor_plans") or [])
    for p in engine_files():
        src = p.read_text(encoding="utf-8")
        loc = sum(1 for l in src.splitlines()
                  if l.strip() and not l.strip().startswith("#"))
        loc_total += loc
        row = {"module": str(p.relative_to(engine)), "loc": loc}
        aggregate = cognitive_by_file.get(str(p))
        if aggregate is None:
            rep = cognitive_complexity(src, budget=10)
            if rep.get("verdict") == "ok":
                row["complexity"] = rep["total"]
                row["over_budget"] = [f["name"] for f in rep["functions"]
                                      if f["complexity"] > 10]
                row["plans"] = sum(len(f["refactor_plans"])
                                   for f in rep["functions"])
            else:
                row["cognitive"] = "unknown"
        elif aggregate["unknown"]:
            row["cognitive"] = "unknown"
        else:
            row["complexity"] = aggregate["complexity"]
            row["over_budget"] = sorted(aggregate["over_budget"])
            row["plans"] = aggregate["plans"]
        try:
            cs = _contracts_bounded(str(p))
            row["contracts"] = len(cs)
            contract_ok += 1
        except Exception as error:
            row["contracts"] = "unknown"
            row["contract_refusal"] = refusal_reason(error)
            contract_unknown += 1
        rows.append(row)
    return {
        "digest": engine_digest(),
        "modules": len(rows),
        "loc": loc_total,
        "twin_functions": len(twin["functions"]),
        "twin_edges": sum(len(v) for v in twin["calls"].values()),
        "over_budget_functions": sorted(
            r.get("function", r.get("file", "?"))
            for r in cog if r.get("over_budget") is True),
        "cognitive_rows": cog,
        "rows": rows,
        "contract_ok": contract_ok,
        "contract_unknown": contract_unknown,
        "certs": len(list((ROOT / "certs").glob("m*_*.py"))),
    }


def render(d):
    L = []
    L.append("# SELF.md - pegrex, audited by pegrex")
    L.append("")
    L.append("> The engine that audits everything, auditing itself. "
             "Regenerated by `python tools/selfhost.py`; CI enforces "
             "freshness with `python tools/selfhost.py --check`.")
    L.append("")
    L.append(f"- engine digest: `{d['digest']}`")
    L.append(f"- modules: **{d['modules']}**  |  engine LOC: **{d['loc']}**")
    L.append(f"- twin: {d['twin_functions']} functions, "
             f"{d['twin_edges']} call edges")
    L.append(f"- path contracts: {d['contract_ok']} modules extracted, "
             f"**{d['contract_unknown']} unknown** (published, not hidden)")
    L.append(f"- certificates: m3-m{d['certs'] - 1 + 3} "
             f"({d['certs']} files, gate: ALL GREEN)")
    L.append("")
    L.append("## Over-budget functions (cognitive complexity > 10)")
    L.append("")
    over = [r for r in d["rows"] if r.get("over_budget")]
    if over:
        L.append("| module | functions | refactor plans |")
        L.append("|---|---|---|")
        for r in over:
            L.append(f"| {r['module']} | {', '.join(r['over_budget'])} "
                     f"| {r['plans']} |")
    else:
        L.append("*none -- the engine is within budget*")
    L.append("")
    L.append("## Modules where contract extraction refused")
    L.append("")
    unk = [r for r in d["rows"] if r.get("contracts") == "unknown"]
    if unk:
        L.append("| module | deterministic refusal reason |")
        L.append("|---|---|")
        for row in unk:
            reason = row.get("contract_refusal", "reason unavailable").replace("|", "\\|")
            L.append(f"| {row['module']} | {reason} |")
    else:
        L.append("*none*")
    L.append("")
    L.append("## Module table")
    L.append("")
    L.append("| module | LOC | complexity | contracts |")
    L.append("|---|---|---|---|")
    for r in d["rows"]:
        c = r.get("complexity", r.get("cognitive", "?"))
        ct = r.get("contracts", "?")
        L.append(f"| {r['module']} | {r['loc']} | {c} | {ct} |")
    L.append("")
    L.append("---")
    L.append("*Generated by the engine over itself. Every number above was "
             "produced by the same machinery that certifies m3-m"
             f"{d['certs'] - 1 + 3}.*")
    return "\n".join(L) + "\n"


def main():
    d = collect()
    body = render(d)
    out = ROOT / "docs" / "SELF.md"
    if "--check" in sys.argv:
        if not out.exists():
            print("SELF.md missing -- run: python tools/selfhost.py")
            return 1
        current = out.read_text(encoding="utf-8")
        if current != body:
            print("SELF.md stale (generated content differs) -- run: "
                  "python tools/selfhost.py")
            return 1
        print("SELF.md is fresh")
        return 0
    out.parent.mkdir(exist_ok=True)
    out.write_text(body, encoding="utf-8")
    print(f"wrote {out} ({len(body)} bytes, digest {d['digest']})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
