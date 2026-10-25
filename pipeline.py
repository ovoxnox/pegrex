#!/usr/bin/env python
"""Agentic translation pipeline -- driven by a ProjectSpec JSON.

Usage: python pipeline.py specs/fact.json

Stages: PREPROCESS (parse each variant with its language's lpegrex
grammar) -> CFG -> path formulas -> POSTPROCESS (cross-variant invariant:
identical path-constraint sets; plus spec-listed invariant expressions).
"""
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))


def _grammar_file(name: str) -> pathlib.Path:
    """Resolve bundled grammars from a checkout or an installed wheel."""
    candidates = (ROOT / "examples" / name,
                  ROOT / "pegrex" / "grammars" / name,
                  ROOT / "grammars" / name)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(f"bundled grammar {name!r} is missing from: " +
                            ", ".join(str(path) for path in candidates))

from pegrex import compile_grammar, peg
from pegrex.peg import Node
from pegrex.cfg import CFGBuilder, TagSpec
from pegrex.paths import PathEnumerator
from pegrex.sym import V, const, Eq, Not, Lt, Le, Gt, Ge
from pegrex.idioms import IdiomRule, translate
from pegrex.summaries import render_lua, render_c, path_summaries

OPS = {"eq": Eq, "==": Eq, "lt": Lt, "<": Lt, "le": Le, "<=": Le,
       "gt": Gt, ">": Gt, "ge": Ge, ">=": Ge,
       "ne": lambda a, b: Not(Eq(a, b)), "~=": lambda a, b: Not(Eq(a, b)),
       "!=": lambda a, b: Not(Eq(a, b))}


def _operand_lua(x):
    if isinstance(x, Node):
        if x.tag == "Id":
            return V(x.children[0])
        if x.tag == "Number":
            return const(x.children[0])
    return const(x)


def _cond_lua(node):
    a, op, b = node.children[0], node.children[1], node.children[2]
    return OPS[op](_operand_lua(a), _operand_lua(b))


def _cond_c(node, src):
    if isinstance(node, list) and len(node) == 1 and isinstance(node[0], Node):
        return _cond_c(node[0], src)
    ch = node if isinstance(node, list) else \
        [c for c in node.children if isinstance(c, (Node, str))]
    if len(ch) < 3:
        raise ValueError(f"cannot translate condition: {node!r}")
    a, opn, b = ch[0], ch[1], ch[2]

    def operand(x):
        if isinstance(x, Node) and x.tag == "identifier":
            return V(x.children[0])
        if isinstance(x, str):
            try:
                return const(int(x, 0))
            except ValueError:
                return V(x)
        return const(x)

    if isinstance(opn, Node):  # operator text from source span
        op = src[opn.pos:opn.endpos].strip()
    elif isinstance(opn, str) and opn in OPS:
        op = opn
    else:
        op = str(opn)
    return OPS[op](operand(a), operand(b))


#def lua_frontend():
#    gram = _grammar_file("lua.gram").read_text(encoding="utf-8")
#    start, rules = compile_grammar(gram)
#
#    def parse(src):
#        ast, err, _ = peg.run(start, src, rules)
#        assert err is None, err
#        return ast.children[0].children[2]  # FuncDecl -> Block
#
#    return parse, TagSpec(), lambda src: (lambda node: _cond_lua(node))


def c_frontend():
    gram = _grammar_file("c11.gram").read_text(encoding="utf-8")
    typedefs = set()

    def is_typedef(s, pos, node):
        return node.children[0] in typedefs

    def set_typedef(s, pos, *caps):
        node = next((c for c in caps if isinstance(c, Node)), None)
        d = node
        while d is not None and d.tag != "identifier":
            kids = [k for k in getattr(d, "children", [])
                    if isinstance(k, Node)]
            d = kids[0] if kids else None
        if d is not None:
            typedefs.add(d.children[0])
        return True

    defs = {"is_typedef": is_typedef, "set_typedef": set_typedef}
    start, rules = compile_grammar(gram, defs=defs)

    def parse(src, _name=None):
        if _name is not None:
            bodies = c_functions(src)
            if _name not in bodies:
                raise ValueError(f"no C function named {_name!r} found")
            return bodies[_name]
        ast, err, _ = peg.run(start, src, rules, defs=defs)
        assert err is None, err

        def first_node(x, tag):
            if isinstance(x, Node):
                if x.tag == tag:
                    return x
                for c in x.children:
                    r = first_node(c, tag)
                    if r is not None:
                        return r
            elif isinstance(x, list):
                for c in x:
                    r = first_node(c, tag)
                    if r is not None:
                        return r
            return None
        return first_node(ast, "compound-statement")

    def c_while(ch):
        nodes = [c for c in ch if isinstance(c, Node)]
        body = nodes[-1]
        return (ch[:ch.index(body)], body)
    c_while._tag = "iteration-statement"
    tagspec = TagSpec(if_="selection-statement", while_=c_while,
                      block="compound-statement", return_="jump-statement")
    return parse, tagspec, lambda src: (lambda node: _cond_c(node, src))


def ts_frontend(lang):
    """Registry-backed Tree-sitter frontend with a stdlib Python fallback."""
    import re
    from pegrex.tree_sitter_bridge import parse as bridge_parse, TAGSPECS
    from pegrex.languages import get_language, normalize_language
    lang = normalize_language(lang) or lang
    spec = get_language(lang)
    tag_spec_lang = spec.tag_spec or lang

    def parse(src, _name=None, tree=None):
        from pegrex.peg import Node as _N
        if lang == "python":
            tree = bridge_parse(lang, src) if tree is None else tree
            if tree.tag == "module":
                from pegrex.python_ast import parse_function_body
                body = parse_function_body(src, _name)
            else:
                body = tree
        else:
            tree = bridge_parse(lang, src) if tree is None else tree
            body = _first_function(tree, lang, _name)
        block_tag = getattr(TAGSPECS.get(tag_spec_lang), "block", "block")
        if not isinstance(block_tag, str) or block_tag.startswith("__"):
            block_tag = "block"
        skip_tags = ("signature", "parameters", "identifier", "modifiers",
                     "function_value_parameters", "formal_parameters", "type",
                     "user_type", "type_identifier", "nullable_type")
        if body is not None and body.tag in ("function_definition", "function_declaration", "function_item"):
            kids = [c for c in body.children if getattr(c, "tag", "") not in skip_tags]
            if len(kids) == 1 and kids[0].tag in ("block", "statement_block", "statements"):
                return kids[0]
            body = _N(block_tag, body.pos, body.endpos, kids)
        elif body is not None and body.tag not in ("block", "statement_block", "statements"):
            body = _N(block_tag, body.pos, body.endpos, list(body.children))
        return body

    _OPS = {"<": Lt, "<=": Le, ">": Gt, ">=": Ge,
            "==": Eq, "!=": lambda a, b: Not(Eq(a, b))}

    def make_cond(src):
        def atom(txt):
            t = txt.strip()
            if t.startswith("(") and t.endswith(")"):
                t = t[1:-1].strip()
            m = re.match(r"\s*([A-Za-z_]\w*)\s*(<=|>=|<|>|==|!=)\s*"
                         r"(-?\d+|[A-Za-z_]\w*)$", t)
            if not m:
                # full expression fragment (a+1 < b, calls,
                # fields) via the typed IR; bare booleans become opaque
                # atoms; anything else refuses loudly instead of crashing.
                try:
                    try:
                        from .ir import lower_condition as _lower
                    except ImportError: # pipeline imported top-level
                        from pegrex.ir import lower_condition as _lower
                    return _lower(t)
                except Exception:
                    if re.match(r"^[A-Za-z_]\w*$", t):
                        return V(t)
                    raise
            a, b = m.group(1), m.group(3)
            av = V(a) if not a.lstrip("-").isdigit() else const(int(a))
            bv = V(b) if not b.lstrip("-").isdigit() else const(int(b))
            return _OPS[m.group(2)](av, bv)

        def cond(node, _s=src):
            txt = node.children[0] if node.children and \
                isinstance(node.children[0], str) else _s[node.pos:node.endpos]
            txt = txt.strip()
            # compound conditions: split on `and`/`&&` (conjoin) and
            # `or`/`||` (disjoin) -- short-circuit becomes And/Or trees
            or_parts = re.split(r"\s*(?:or|\|\|)\s*", txt)
            if len(or_parts) > 1:
                from pegrex.sym import Or as _Or
                return _Or(*[atom(x) for x in or_parts])
            parts = re.split(r"\s*(?:and|&&)\s*", txt)
            if len(parts) > 1:
                from pegrex.sym import And as _And
                return _And(*[atom(x) for x in parts])
            return atom(txt)
        return cond

    def render(st, src=None):
        t = st.children[0] if st.children and isinstance(st.children[0], str) \
            else (src or "")[st.pos:st.endpos]
        return t.replace("return", "").strip()

    return parse, TAGSPECS[tag_spec_lang], make_cond


def _first_function(tree, lang, name=None):
    from pegrex.peg import Node as _N
    from pegrex.languages import get_language
    spec = get_language(lang)
    tag_language = spec.tag_spec or spec.name
    tag_spec = get_language(tag_language)
    fn_tag = spec.function_tag or tag_spec.function_tag
    if not fn_tag:
        raise ValueError(f"no function node tag registered for {lang!r}")
    first = [None]

    def walk(n):
        if isinstance(n, _N):
            if n.tag == fn_tag and first[0] is None:
                kids = [c for c in n.children if isinstance(c, _N)]
                fn_name = next((str(c.children[0]) for c in kids
                                if c.tag in {"identifier", "type_identifier"} and c.children), None)
                if name is None or fn_name == name:
                    first[0] = n  # the selected function node itself
            for c in n.children:
                walk(c)
        elif isinstance(n, list):
            for c in n:
                walk(c)
    walk(tree)
    assert first[0] is not None, f"no {fn_tag} in source"
    return first[0]


def go_frontend():
    return ts_frontend("go")


def rust_frontend():
    return ts_frontend("rust")


def python_frontend():
    return ts_frontend("python")


def javascript_frontend():
    return ts_frontend("javascript")


def solidity_frontend():
    return ts_frontend("solidity")


def julia_frontend():
    return ts_frontend("julia")


def kotlin_frontend():
    return ts_frontend("kotlin")


def zig_frontend():
    return ts_frontend("zig")


def typescript_frontend():
    """Typescript shares the parser binding and CFG tags registered for JS."""
    return ts_frontend("typescript")


from pegrex.languages import frontend_registry as _frontend_registry
_FRONTEND_FACTORY_NAMES = _frontend_registry()
FRONTENDS = {language: globals()[factory_name]
             for language, factory_name in _FRONTEND_FACTORY_NAMES.items()
             if callable(globals().get(factory_name))}


def frontend_for(language):
    """Resolve a contract frontend via the central capability registry."""
    from pegrex.languages import get_contract_frontend
    return get_contract_frontend(language)()


def lua_functions(src):
    """Parse a chunk; return {name: body} for every local function."""
    import pegrex as _p
    start, rules = compile_grammar(_grammar_file("lua.gram").read_text(encoding="utf-8"))
    ast, err, _ = peg.run(start, src, rules)
    assert err is None, err
    return {f.children[0].children[0]: f.children[2] for f in ast.children}


def python_functions(src, tree=None):
    """Return {name: body} for every top-level Python function.

    Language selection and parser fallback are owned by tree_sitter_bridge;
    this helper only extracts the historical compatibility view.
    """
    from pegrex.tree_sitter_bridge import parse as parse_source
    from pegrex.peg import Node
    tree = parse_source("python", src) if tree is None else tree
    out = {}
    def walk(node):
        if isinstance(node, Node):
            if node.tag == "function_definition":
                children = [child for child in node.children if isinstance(child, Node)]
                if len(children) >= 2 and children[0].tag == "identifier":
                    name = children[0].children[0] if children[0].children else None
                    body = next((child for child in reversed(children)
                                 if child.tag in ("block", "statement_block", "statements")), None)
                    if name and body is not None:
                        out[str(name)] = body
            # Do not walk nested functions under an outer function again as
            # top-level entries; nested names are handled by the owning scope.
            if node.tag != "function_definition":
                for child in node.children:
                    walk(child)
        elif isinstance(node, list):
            for child in node:
                walk(child)
    walk(tree)
    return out


def c_functions(src):
    """Parse translation-unit; return {name: body} per function definition.

    Name recovered from the declarator that precedes each top-level
    compound-statement (DFS order pairs them).
    """
    from pegrex.summaries import render_c as _rc
    parse, _, _ = c_frontend()
    import pegrex as _p
    typedefs = set()
    def is_typedef(s, pos, node): return node.children[0] in typedefs
    def set_typedef(s, pos, *caps):
        node = next((c for c in caps if isinstance(c, Node)), None)
        d = node
        while d is not None and d.tag != "identifier":
            kids = [k for k in getattr(d, "children", [])
                    if isinstance(k, Node)]
            d = kids[0] if kids else None
        if d is not None:
            typedefs.add(d.children[0])
        return True
    defs = {"is_typedef": is_typedef, "set_typedef": set_typedef}
    start, rules = compile_grammar(_grammar_file("c11.gram").read_text(encoding="utf-8"),
                                   defs=defs)
    ast, err, _ = peg.run(start, src, rules, defs=defs)
    assert err is None, err
    # function-definition is a plain rule: caps flatten to a repeating
    # [declaration-specifiers, direct-declarator, compound-statement] triple
    items = [x for x in (ast if isinstance(ast, list) else [ast])
             if isinstance(x, Node)]
    out = {}
    i = 0
    while i + 2 < len(items) + 1 and i + 2 <= len(items):
        spec, ddecl, comp = items[i], items[i + 1], items[i + 2]
        if comp.tag == "compound-statement" and ddecl.tag == "direct-declarator":
            out[ddecl.children[0].children[0]] = comp
            i += 3
        else:i += 1
    return out


FUNCTIONS = {"c": c_functions, "python": python_functions}


def c_parse_full(src):
    """Parse a C translation unit and return the whole AST (unlike
    c_frontend().parse, which extracts a single function body)."""
    gram = _grammar_file("c11.gram").read_text(encoding="utf-8")
    typedefs = set()

    def is_typedef(s, pos, node):
        return node.children[0] in typedefs

    def set_typedef(s, pos, *caps):
        node = next((c for c in caps if isinstance(c, Node)), None)
        d = node
        while d is not None and d.tag != "identifier":
            kids = [k for k in getattr(d, "children", [])
                    if isinstance(k, Node)]
            d = kids[0] if kids else None
        if d is not None:
            typedefs.add(d.children[0])
        return True

    defs = {"is_typedef": is_typedef, "set_typedef": set_typedef}
    start, rules = compile_grammar(gram, defs=defs)
    ast, err, _ = peg.run(start, src, rules, defs=defs)
    assert err is None, err
    return ast


def path_constraints(cfg, cond, unroll):
    out = []
    for path in PathEnumerator(cfg, unroll=unroll).enumerate():
        cons = []
        for i in range(len(path) - 1):
            for dst, e in cfg.successors(path[i]):
                if dst != path[i + 1] or e.cond is None:
                    continue
                if e.kind in ("then", "body"):
                    cons.append(cond(e.cond))
                elif e.kind in ("else", "exit"):
                    base = e.cond[0] if isinstance(e.cond, tuple) else e.cond
                    cons.append(Not(cond(base)))
        out.append(frozenset(str(c) for c in cons))
    return sorted(out, key=str)


def _invariant_value(expression: str, results: dict):
    """Evaluate a small data-only invariant language, never Python builtins."""
    import ast
    tree = ast.parse(expression, mode="eval")

    def value(node):
        if isinstance(node, ast.Expression):
            return value(node.body)
        if isinstance(node, ast.Constant):
            return node.value
        if isinstance(node, ast.Name) and node.id == "results":
            return results
        if isinstance(node, ast.Subscript):
            return value(node.value)[value(node.slice)]
        if isinstance(node, ast.List):
            return [value(x) for x in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(value(x) for x in node.elts)
        if isinstance(node, ast.BoolOp):
            values = [value(x) for x in node.values]
            return all(values) if isinstance(node.op, ast.And) else any(values)
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
            return not value(node.operand)
        if isinstance(node, ast.Compare):
            left = value(node.left)
            for op, comparator in zip(node.ops, node.comparators):
                right = value(comparator)
                if isinstance(op, ast.Eq): ok = left == right
                elif isinstance(op, ast.NotEq): ok = left != right
                elif isinstance(op, ast.Lt): ok = left < right
                elif isinstance(op, ast.LtE): ok = left <= right
                elif isinstance(op, ast.Gt): ok = left > right
                elif isinstance(op, ast.GtE): ok = left >= right
                elif isinstance(op, ast.In): ok = left in right
                elif isinstance(op, ast.NotIn): ok = left not in right
                else: raise ValueError(f"unsupported comparison: {type(op).__name__}")
                if not ok:
                    return False
                left = right
            return True
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) \
                and node.func.id in ("len", "sum", "min", "max") \
                and not node.keywords:
            return {"len": len, "sum": sum, "min": min, "max": max}[
                node.func.id](*[value(x) for x in node.args])
        raise ValueError(f"unsupported invariant syntax: {ast.dump(node, include_attributes=False)}")

    return value(tree)


def _postprocess(spec: dict, results: dict) -> None:
    """Check cross-variant identity, materialize artifacts, and evaluate data invariants."""
    langs = [variant["language"] for variant in spec["variants"]]
    for lang in langs[1:]:
        if results[lang] != results[langs[0]]:
            raise ValueError(f"invariant violated: {langs[0]} != {lang}")
        if results[lang + ":contract"] != results[langs[0] + ":contract"]:
            raise ValueError(f"contract mismatch: {langs[0]} != {lang}")
        if (lang + ":whole") in results and (langs[0] + ":whole") in results:
            if results[lang + ":whole"] != results[langs[0] + ":whole"]:
                raise ValueError(f"whole-program mismatch: {langs[0]} != {lang}")
    post = spec.get("postprocess", {})
    for artifact in post.get("expected_artifacts", []):
        text = results.get("artifacts", {}).get(pathlib.Path(artifact).name)
        if text is not None and "artifacts/" not in artifact:
            out = ROOT / artifact
            if not out.exists():
                out.write_text(text + "\n")
            if not out.exists():
                raise ValueError(f"missing artifact {artifact}")
            print(f"  artifact: {artifact}")
    for invariant in post.get("invariants", []):
        if not _invariant_value(invariant, results):
            raise ValueError(f"invariant violated: {invariant}")
    print("POSTPROCESS invariants hold -- certificate issued")


def run_spec(spec_path):
    spec = json.loads((ROOT / spec_path).read_text())
    print(f"== pipeline: {spec['name']} ==")
    results = {}
    from pegrex.languages import normalize_language, get_language
    for variant in spec["variants"]:
        requested_lang = variant["language"]
        lang = normalize_language(requested_lang)
        if lang is None:
            raise ValueError(f"unsupported language in spec: {requested_lang!r}")
        language_spec = get_language(lang)
        if "contracts" not in language_spec.capabilities:
            raise NotImplementedError(
                f"contract extraction unsupported for {lang}: {language_spec.notes}")
        src = (ROOT / variant["source"]).read_text(encoding="utf-8")
        parse, tagspec, make_cond = frontend_for(lang)
        body = parse(src)      # PREPROCESS
        cfg = CFGBuilder(tagspec).build(body)  # CFG
        results[lang] = path_constraints(cfg, make_cond(src),
                                         spec.get("unroll", 1))
        if "entry" in variant: # multi-function variant
            from pegrex.summaries import expand_calls, path_summaries as _ps
            if lang == "lua":
                _render = lambda st: render_lua(st)
            elif lang == "c":
                _render = lambda st: render_c(st, src)
            else:
                def _render(st, _s=src):
                    t = st.children[0] if st.children and \
                        isinstance(st.children[0], str) else _s[st.pos:st.endpos]
                    return t.replace("return", "").strip()
            fn_bodies = FUNCTIONS[lang](src)
            fn_contracts = {nm: _ps(CFGBuilder(tagspec).build(b),
                                    make_cond(src), _render,
                                    spec.get("unroll", 1))
                            for nm, b in fn_bodies.items()}
            pnames = variant.get("params", {})
            entry = variant["entry"]
            whole = fn_contracts[entry]
            callees = {nm: c for nm, c in fn_contracts.items() if nm != entry}
            whole = expand_calls(whole, callees, pnames)
            results[lang + ":whole"] = whole
            print(f"  [{lang}] whole-program contract of {entry}:")
            for cons, res in whole:
                print(f"      {sorted(cons)} -> {res}")
        if lang == "lua":
            _render = lambda st: render_lua(st)
        elif lang == "c":
            _render = lambda st: render_c(st, src)
        else:  # tree-sitter frontends (python/go/rust)
            def _render(st, _s=src):
                t = st.children[0] if st.children and \
                    isinstance(st.children[0], str) else _s[st.pos:st.endpos]
                return t.replace("return", "").strip()
        results[lang + ":contract"] = path_summaries(
            cfg, make_cond(src), _render, spec.get("unroll", 1))
        print(f"  [{lang}] contract:")
        for cons, res in results[lang + ":contract"]:
            print(f"      {sorted(cons)} -> {res}")
        print(f"  [{lang}] {variant['source']}: {len(results[lang])} paths")
        # IDIOM STAGE: rewrite idioms whose path guards hold; emit artifacts
        for ir in spec.get("idiom_rules", []):
            if ir.get("source_language") != lang:
                continue
            rule = IdiomRule(ir["name"], ir["source_tags"],
                             ir["target_template"], ir.get("path_guard"),
                             ir.get("slots", {}))
            emitted = translate(body, [rule], results[lang], src=src)
            if not emitted:
                raise ValueError(f"idiom {ir['name']!r} matched nothing on {lang}")
            for name, text in emitted:
                print(f"  idiom[{lang}] {name}: {text}")
                results.setdefault("artifacts", {})[ir["name"]] = text
        for p in results[lang]:
            print(f"      {sorted(p)}")
    _postprocess(spec, results)
    return results


if __name__ == "__main__":
    run_spec(sys.argv[1] if len(sys.argv) > 1 else "specs/fact.json")



def mir_frontend():
    """MIR (rustc --emit=mir) -> CFG, no tree-sitter: MIR is already
    basic blocks + terminators.  A fourth frontend kind: compiler IR."""
    from pegrex import compile_grammar, peg
    from pegrex.peg import Node as _N
    from pegrex.cfg import CFG
    from pegrex.sym import V, const, Eq

    gram = _grammar_file("mir.gram").read_text(encoding="utf-8")
    start_r, rules = compile_grammar(gram)

    def parse(mir_text):
        return mir_text

    def cfg_from_mir(mir_text):
        """Parse each bbN: { ... } block with its OWN grammar run (fresh Ctx
        per call sidesteps any cross-block state coupling), then wire edges."""
        import re as _re
        from pegrex.peg import Node as _N
        from pegrex.cfg import CFG
        from pegrex.sym import V, const, Eq

        # split into blocks: header text + each 'bbN: {...}' section
        sections = _re.split(r"(?=\s*bb\d+\s*:)", mir_text)
        header, blocks_text = sections[0], [s for s in sections[1:]
                                            if _re.match(r"\s*bb\d+\s*:", s)]
        cfg = CFG()
        ids, handles = [], {}
        for bt in blocks_text:
            bid = int(_re.match(r"\s*bb(\d+)\s*:", bt).group(1))
            handles[bid] = cfg.add_block()
            ids.append((bid, bt))
        for bid, bt in ids:
            b = handles[bid]
            # statements via regex (robust across rustc dump layout drift);
            # the mir.gram grammar remains the corpus showcase.
            cfg.blocks[b].stmts = [f"{m.group(1)} = {m.group(2).strip()}"
                                   for m in _re.finditer(
                                       r"(_\d+)\s*=\s*([^;]+);", bt)]
            if _re.search(r"\breturn\b", bt):
                cfg.blocks[b].term = "ret"
            elif "switchInt" in bt:
                cfg.blocks[b].term = "branch"
                m = _re.search(r"switchInt\(([^)]*)\)\s*->\s*\[(.*?)\]",
                               bt, _re.S)
                cond_txt = m.group(1).strip() if m else "_"
                for am in _re.finditer(r"(\d+)\s*:\s*bb(\d+)", m.group(2)):
                    tgt = int(am.group(2))
                    if tgt not in handles:
                        handles[tgt] = cfg.add_block()
                    guard = Eq(V(cond_txt), const(int(am.group(1))))
                    first = am.start() == 0
                    cfg.add_edge(b, handles[tgt],
                                 guard if first else (guard, "else"),
                                 "then" if first else "else")
                om = _re.search(r"otherwise\s*:\s*bb(\d+)", bt)
                if om:
                    tgt = int(om.group(1))
                    if tgt not in handles:
                        handles[tgt] = cfg.add_block()
                    cfg.add_edge(b, handles[tgt], (guard, "else"), "else")
            else:  # goto
                gm = _re.search(r"goto\s*->\s*bb(\d+)", bt)
                if gm:
                    tgt = int(gm.group(1))
                    if tgt not in handles:
                        handles[tgt] = cfg.add_block()
                    cfg.add_edge(b, handles[tgt], kind="flow")
        return cfg

    return parse, cfg_from_mir, None


def mlir_frontend():
    """MLIR text -> CFG, regex-native (mirrors the MIR frontend pattern)."""
    from pegrex.cfg import CFG
    import re as _re
    from pegrex.sym import V, const, Eq

    def parse(text):
        return text

    def cfg_from_mlir(text):
        # split into top-level blocks between braces; operations are lines
        cfg = CFG()
        blocks, edges = {}, []
        # candidate blocks: lines with ops ending in cf.br / cf.cond_br
        lines = text.splitlines()
        cur = cfg.add_block()
        blocks[cur] = cur
        for ln in lines:
            mname = _re.match(r"\s*([%a-zA-Z_][\w.]*)\s*(.*)", ln)
            if not mname:
                continue
            op = mname.group(1)
            if op in ("cf.br", "cf.cond_br", "return", "func.return"):
                cfg.blocks[cur].term = "branch" if op == "cf.cond_br" else "ret"
            if op == "cf.cond_br":
                m = _re.search(r"\(([^)]*)\)", mname.group(2))
                tgt = _re.findall(r"\^(\w+)", mname.group(2))
                guard_src = m.group(1).strip() if m else "_"
                guard = Eq(V(guard_src), const(0))
                for i, t in enumerate(tgt):
                    nb = cfg.add_block()
                    blocks[nb] = nb
                    cfg.add_edge(cur, nb, guard if i == 0 else (guard, "else"),
                                 "then" if i == 0 else "else")
                    cur = nb
                    break  # first target only; linear chain demo
        return cfg

    return parse, cfg_from_mlir, None
