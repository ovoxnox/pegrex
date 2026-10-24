"""
rosetta 

║  Semantic diff as a universal language: N-way cross-language equivalence  
║  over path contracts.  Every variant is lowered exactly the way           
║  pipeline.run_spec lowers it (same frontends, same path_constraints,      
║  same path_summaries, same functions + expand_calls for multi-function    
║  variants); an ordered pair (i, j) is "equivalent" iff BOTH the raw       
║  constraint sets and the contract lists are equal — otherwise the pair    
║  carries a counterexample quoting the first differing path/contract from  
║  each side. 

║  Three-valued: unknown languages, parse failures, and unsupported 
║  multi-function variants are recorded in "refusals" (and pairs touching   
║  them are "refused") — never silently dropped, never a guessed verdict."""

from __future__ import annotations

import json
import pathlib

from .cfg import CFGBuilder
from .summaries import expand_calls, path_summaries, render_c, render_lua


class RosettaError(ValueError):
    """Spec outside the supported shape — loud refusal, never a guess."""


def _load_spec(spec):
    """-> (data, base_dir).  A str is a path to the spec JSON; relative
    source paths resolve against the spec file's directory."""
    if isinstance(spec, (str, pathlib.Path)):
        spec_path = pathlib.Path(spec)
        return json.loads(spec_path.read_text()), spec_path.parent
    if isinstance(spec, dict):
        return spec, pathlib.Path.cwd()
    raise RosettaError(f"rosetta: spec must be a dict or a path, got "
                       f"{type(spec).__name__}")


def _renderer(lang: str, src: str):
    if lang == "lua":
        return lambda st: render_lua(st)
    if lang == "c":
        return lambda st: render_c(st, src)

    def _render(st, _s=src):
        t = st.children[0] if st.children and \
            isinstance(st.children[0], str) else _s[st.pos:st.endpos]
        return t.replace("return", "").strip()
    return _render


def _build_variant(variant, base_dir, unroll):
    """pipeline.run_spec's per-variant lowering, verbatim.  Returns
    {"language", "constraints", "contracts", "whole": None|list, "source"}
    or raises _VariantRefused with a loud reason."""
    import pipeline
    lang = variant.get("language")
    if lang not in pipeline.FRONTENDS:
        raise _VariantRefused(f"unknown language {lang!r} — no frontend")
    src_path = pathlib.Path(variant["source"])
    if not src_path.is_absolute():
        src_path = base_dir / src_path
    src = src_path.read_text()
    parse, tagspec, make_cond = pipeline.FRONTENDS[lang]()
    try:
        body = parse(src)   # PREPROCESS
    except Exception as e:
        raise _VariantRefused(f"[{lang}] parse failure in {src_path.name}: "
                              f"{type(e).__name__}: {e}")
    cfg = CFGBuilder(tagspec).build(body)   # CFG
    cond = make_cond(src)
    constraints = pipeline.path_constraints(cfg, cond, unroll)
    render = _renderer(lang, src)
    contracts = path_summaries(cfg, cond, render, unroll)
    whole = None
    if "entry" in variant:  # multi-function variant
        if lang not in pipeline.FUNCTIONS:
            raise _VariantRefused(
                f"[{lang}] multi-function variant (entry="
                f"{variant['entry']!r}) unsupported — no FUNCTIONS entry "
                f"for {lang!r}")
        fn_bodies = pipeline.FUNCTIONS[lang](src)
        fn_contracts = {nm: path_summaries(CFGBuilder(tagspec).build(b),
                                           cond, render, unroll)
                        for nm, b in fn_bodies.items()}
        pnames = variant.get("params", {})
        entry = variant["entry"]
        callees = {nm: c for nm, c in fn_contracts.items() if nm != entry}
        whole = expand_calls(fn_contracts[entry], callees, pnames)
    return {"language": lang, "constraints": constraints,
            "contracts": contracts, "whole": whole, "source": str(src_path)}


class _VariantRefused(ValueError):
    pass


def _quote_path(p) -> str:
    return "[" + ", ".join(sorted(str(c) for c in p)) + "]"


def _quote_contract(t) -> str:
    cons, res = t
    return f"{_quote_path(cons)} -> {res!r}"


def _first_diff(a, b):
    """Index of first differing element; None if equal prefix and same len."""
    for i, (x, y) in enumerate(zip(a, b)):
        if x != y:
            return i
    if len(a) != len(b):
        return min(len(a), len(b))
    return None


def _compare_pair(va, vb):
    """-> (verdict, detail).  Equivalent iff raw constraints and contracts
    are equal (whole-program contracts too when both sides have them —
    mirroring run_spec's POSTPROCESS)."""
    detail = {}
    ci = _first_diff(va["constraints"], vb["constraints"])
    if ci is not None:
        qa = _quote_path(va["constraints"][ci]) if ci < len(va["constraints"]) \
            else "<no such path>"
        qb = _quote_path(vb["constraints"][ci]) if ci < len(vb["constraints"]) \
            else "<no such path>"
        detail["constraints"] = {"a": qa, "b": qb, "first_diff_index": ci}
    ti = _first_diff(va["contracts"], vb["contracts"])
    if ti is not None:
        qa = _quote_contract(va["contracts"][ti]) if ti < len(va["contracts"]) \
            else "<no such contract>"
        qb = _quote_contract(vb["contracts"][ti]) if ti < len(vb["contracts"]) \
            else "<no such contract>"
        detail["contracts"] = {"a": qa, "b": qb, "first_diff_index": ti}
    if va["whole"] is not None and vb["whole"] is not None:
        wi = _first_diff(va["whole"], vb["whole"])
        if wi is not None:
            qa = _quote_contract(va["whole"][wi]) if wi < len(va["whole"]) \
                else "<no such whole-contract>"
            qb = _quote_contract(vb["whole"][wi]) if wi < len(vb["whole"]) \
                else "<no such whole-contract>"
            detail["whole"] = {"a": qa, "b": qb, "first_diff_index": wi}
    return ("equivalent", None) if not detail else ("counterexample", detail)


def equivalence(spec) -> dict:
    """N-way cross-language equivalence over path contracts.

    spec: {"name": str, "variants": [{"language", "source", "entry"?,
    "params"?} x N>=2]} — or a path to such JSON (relative source paths
    resolve against the spec file's directory).

    Returns {"name", "pairs": [{"a", "b", "verdict", "detail"?}], "n_ways",
    "refusals"}.  Pair verdicts: "equivalent" | "counterexample" (detail
    quotes the first differing path/contract from each side) | "refused"
    (a variant on one side could not be built — see "refusals").
    n_ways: "equivalent" iff every pair is equivalent; "counterexample" if
    any pair disagrees; "refused" when nothing disagreed but some pair
    could not be judged.  <2 variants raises RosettaError."""
    data, base_dir = _load_spec(spec)
    name = data.get("name", "unnamed")
    variants = data.get("variants") or []
    if len(variants) < 2:
        raise RosettaError(f"rosetta: need >= 2 variants for an N-way "
                           f"equivalence, got {len(variants)}")
    unroll = data.get("unroll", 1)
    import pipeline  # noqa: F401  (frontends live in the ops layer)
    built, refusals, failed = [], [], {}
    for idx, variant in enumerate(variants):
        lang = variant.get("language", f"variant#{idx}")
        try:
            built.append(_build_variant(variant, base_dir, unroll))
        except _VariantRefused as e:
            reason = str(e)
            refusals.append(reason)
            failed[idx] = reason
            built.append(None)
    pairs = []
    any_counter, any_refused = False, False
    for i in range(len(built)):
        for j in range(len(built)):
            if i == j:
                continue
            va, vb = built[i], built[j]
            la = variants[i].get("language", f"variant#{i}")
            lb = variants[j].get("language", f"variant#{j}")
            if va is None or vb is None:
                why = failed.get(i) or failed.get(j)
                pairs.append({"a": la, "b": lb, "verdict": "refused",
                              "detail": {"refusal": why}})
                any_refused = True
                continue
            verdict, detail = _compare_pair(va, vb)
            entry = {"a": la, "b": lb, "verdict": verdict}
            if detail:
                entry["detail"] = detail
            pairs.append(entry)
            any_counter |= verdict == "counterexample"
            any_refused |= verdict == "refused"
    n_ways = "counterexample" if any_counter else \
        ("refused" if any_refused else "equivalent")
    return {"name": name, "pairs": pairs, "n_ways": n_ways,
            "refusals": refusals}
