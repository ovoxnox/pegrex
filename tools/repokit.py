"""repokit.py -- repo-scale artifacts: aggregated arch index (D12) and
portable verification bundles (D14: spec + constraints + SMT-LIB in one
JSON artifact a tiny external checker can re-validate)."""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def repo_index(root: str, out: str = "repo.index.json") -> dict:
    """Walk a tree, run mkspec per source file (cached), aggregate into a
    repo-level arch index with import-derived depends_on."""
    import pipeline
    from pegrex.cfg import CFGBuilder
    from pegrex.summaries import path_summaries
    containers = []
    for p in sorted(pathlib.Path(root).rglob("*.py")):
        if "__pycache__" in str(p) or ".vendor" in str(p):
            continue
        try:
            src = p.read_text()
            parse, tags, mk = pipeline.python_frontend()
            body = parse(src)
            fns = pipeline.python_functions(src)
            imports = sorted({l.split()[1].split(".")[0]
                              for l in src.splitlines()
                              if l.startswith(("import ", "from "))})
            modules = [{"file": str(p), "id": name,
                        "boundary": f"{len(fn.children)} children",
                        "depends_on": imports, "owns": []}
                       for name, fn in fns.items()]
            containers.append({"id": p.stem, "path": str(p),
                               "description": f"{len(fns)} functions",
                               "depends_on": imports, "modules": modules})
        except Exception:
            continue
    index = {"containers": containers}
    pathlib.Path(out).write_text(json.dumps(index, indent=1))
    return index


def verification_bundle(source_path: str, out: str | None = None) -> dict:
    """D14: self-contained verification bundle — spec + every path's
    constraints + SMT-LIB + sha.  Re-validatable by any JSON+SMT consumer."""
    import pipeline
    from pegrex.cfg import CFGBuilder
    from pegrex.paths import PathEnumerator, PathFormula
    src = pathlib.Path(source_path).read_text()
    parse, tags, mk = pipeline.python_frontend()
    body = parse(src)
    cfg = CFGBuilder(tags).build(body)
    cond = mk(src)
    paths = []
    for p in PathEnumerator(cfg, unroll=2).enumerate():
        cons = []
        for i in range(len(p) - 1):
            for dst, e in cfg.successors(p[i]):
                if dst == p[i + 1] and e.cond is not None:
                    base = e.cond[0] if isinstance(e.cond, tuple) else e.cond
                    c = cond(base)
                    cons.append(str(c) if e.kind in ("then", "body")
                                else str(__import__("pegrex.sym", fromlist=["Not"]).Not(c)))
        paths.append({"blocks": p, "constraints": sorted(set(cons))})
    bundle = {"source_sha256": __import__("hashlib").sha256(src.encode()).hexdigest(),
              "language": "python", "entrypoint": pathlib.Path(source_path).stem,
              "paths": paths,
              "smt2": PathFormula([], {}, [c for p_ in paths for c in p_["constraints"]]).smt2()}
    if out:
        pathlib.Path(out).write_text(json.dumps(bundle, indent=1))
    return bundle
