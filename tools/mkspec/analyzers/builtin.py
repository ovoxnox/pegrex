"""Built-in analyzers: security, structure, quality, testing, docs, deps."""
import ast
from functools import lru_cache
import pathlib
import re
import sys

from pegrex.peg import Node

from ..core import Finding, analyzer


def _line(src, pos):
    return src[:pos].count("\n") + 1


def _iter(tree):
    stack = [tree]
    while stack:
        n = stack.pop()
        if isinstance(n, Node):
            yield n
            stack.extend(c for c in n.children if isinstance(c, Node))


def _func_bodies(tree):
    tags = {"function_definition", "function_declaration", "function_item"}
    out = []
    def walk(n):
        if isinstance(n, Node):
            if n.tag in tags:
                kids = [c for c in n.children if isinstance(c, Node)]
                name = "(anon)"
                if kids and kids[0].children \
                        and isinstance(kids[0].children[0], str):
                    cand = kids[0].children[0].strip()
                    if cand and (cand[0].isalpha() or cand[0] == "_") \
                            and " " not in cand:
                        name = cand
                out.append((name, n, kids[-1] if kids else n))
            for c in n.children:
                walk(c)
    walk(tree)
    return out


DQ = chr(34)   # "
SQ = chr(39)   # '


@analyzer("security")
def security(ctx):
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent.parent.parent.parent))
    from tools.secaudit import audit as sec_audit
    return [Finding("security", f["id"], f["severity"], f["line"], f["evidence"],
                    fix=f.get("message", "")[:200])
            for f in sec_audit(str(ctx.path), lang=ctx.lang)]


@analyzer("structure")
def structure(ctx):
    if ctx.tree is None:
        return []
    out = []
    BRANCH = ("if_statement", "if_expression", "while_statement",
              "while_expression", "for_statement", "for_clause")
    n_fns = 0
    max_depth = [0]
    def depth(n, d=0):
        if isinstance(n, Node):
            max_depth[0] = max(max_depth[0], d)
            for c in n.children:
                depth(c, d + 1)
    depth(ctx.tree)
    for name, node, body in _func_bodies(ctx.tree):
        n_fns += 1
        span = body.endpos - body.pos
        branches = sum(1 for n in _iter(body) if n.tag in BRANCH)
        out.append(Finding("structure", "function", "INFO", _line(ctx.src, node.pos),
                           name + " (bytes=%d ~lines=%d branches=%d)"
                           % (span, span // 40, branches), symbol=name,
                           metric={"bytes": span, "lines": span // 40,
                                   "branches": branches}))
    out.append(Finding("structure", "file-metrics", "INFO", 0,
                       "loc=%d functions=%d max_nesting=%d"
                       % (ctx.src.count("\n"), n_fns, max_depth[0]),
                       metric={"loc": ctx.src.count("\n"), "functions": n_fns,
                               "max_nesting": max_depth[0]}))
    return out


@analyzer("quality")
def quality(ctx):
    if ctx.tree is None:
        return []
    out = []
    mutable_default_lines = set()
    if ctx.lang == "python":
        try:
            python_tree = ast.parse(ctx.src, filename=str(ctx.path))
        except SyntaxError:
            python_tree = None
        if python_tree is not None:
            for function in ast.walk(python_tree):
                if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                defaults = [*function.args.defaults, *function.args.kw_defaults]
                if any(isinstance(value, (ast.List, ast.Dict, ast.Set))
                       for value in defaults if value is not None):
                    mutable_default_lines.add(function.lineno)
    for name, node, body in _func_bodies(ctx.tree):
        if (body.endpos - body.pos) // 40 > 40:
            out.append(Finding("quality", "long-function", "MEDIUM",
                               _line(ctx.src, node.pos),
                               "%s is long" % name, symbol=name,
                               fix="split into focused helpers"))
    for n in _iter(ctx.tree):
        t = ctx.src[n.pos:n.endpos]
        L = _line(ctx.src, n.pos)
        if n.tag == "except_clause" and re.match(r"except\s*:", t):
            out.append(Finding("quality", "bare-except", "HIGH", L,
                               t.strip()[:70], fix="catch specific exceptions"))
        if n.tag == "function_definition" and (
                L in mutable_default_lines if ctx.lang == "python" else
                re.search(r"\(\s*\w+\s*=\s*[\[{]", t)):
            out.append(Finding("quality", "mutable-default", "HIGH", L,
                               t.strip()[:70], symbol=name,
                               fix="default None + init in body"))
        if n.tag == "global_statement":
            out.append(Finding("quality", "global-statement", "MEDIUM", L,
                               t.strip()[:70], fix="pass state explicitly"))
        if n.tag == "call" and t.startswith("print"):
            out.append(Finding("quality", "print-in-code", "LOW", L,
                               t.strip()[:70], fix="use logging"))
        if re.search(r"#\s*(TODO|FIXME|XXX)\b", t):
            out.append(Finding("quality", "todo-marker", "INFO", L, t.strip()[:70]))
    for m in re.finditer(r"^import\s+(\w+)", ctx.src, re.M):
        if m.group(1) == "*":
            out.append(Finding("quality", "wildcard-import", "MEDIUM",
                               _line(ctx.src, m.start()), m.group(0),
                               fix="import names explicitly"))
    return out


def _tests_root(path):
    """Find the nearest repository test directory, not the source-file folder."""
    for parent in (path.parent, *path.parents):
        candidate = parent / "tests"
        if candidate.is_dir():
            return candidate
        if (parent / "pyproject.toml").exists() or (parent / ".git").exists():
            break
    return None


@lru_cache(maxsize=16)
def _test_symbols(root):
    """Collect static test references; this is evidence, not runtime coverage."""
    identifiers, test_functions = set(), set()
    for path in sorted(root.glob("test_*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                identifiers.add(node.id)
            elif isinstance(node, ast.Attribute):
                identifiers.add(node.attr)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                test_functions.add(node.name)
    return identifiers, test_functions


@analyzer("testing")
def testing(ctx):
    out = []
    root = _tests_root(ctx.path)
    if root is None or ctx.tree is None:
        return out
    identifiers, test_functions = _test_symbols(root)
    for name, node, _body in _func_bodies(ctx.tree):
        if name.startswith("_"):
            continue
        if name not in identifiers and ("test_" + name) not in test_functions:
            out.append(Finding("testing", "untested-function", "MEDIUM",
                               _line(ctx.src, node.pos),
                               "no static test reference found" , symbol=name,
                               fix="add direct happy-path and edge-path tests"))
    return out


@analyzer("documentation")
def documentation(ctx):
    if ctx.tree is None:
        return []
    out = []
    if ctx.lang == "python":
        try:
            tree = ast.parse(ctx.src, filename=str(ctx.path))
        except (SyntaxError, UnicodeError):
            return out
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if node.name.startswith("_") or ast.get_docstring(node):
                continue
            out.append(Finding("documentation", "missing-docstring", "LOW",
                               node.lineno, f"{node.name} has no docstring",
                               symbol=node.name,
                               fix="docstring: purpose, params, returns, raises"))
        return out
    for name, node, body in _func_bodies(ctx.tree):
        if name.startswith("_"):
            continue
        kids = [c for c in node.children if isinstance(c, Node)]
        def is_doc(c):
            if getattr(c, "tag", "") != "block" or not c.children:
                return False
            first = c.children[0]
            if not isinstance(first, str):
                return False
            s = first.lstrip()
            return s[:3] in (DQ * 3, SQ * 3) or s[:1] in (DQ, SQ)
        if not any(is_doc(c) for c in kids[-1:]):
            out.append(Finding("documentation", "missing-docstring", "LOW",
                               _line(ctx.src, node.pos),
                               "%s has no docstring" % name, symbol=name,
                               fix="docstring: purpose, params, returns, raises"))
    return out


@analyzer("dependencies")
def dependencies(ctx):
    stdlib = set(sys.stdlib_module_names)
    groups = {"stdlib": set(), "third_party": set()}
    for m in re.finditer(r"^(?:from|import)\s+(\w+)", ctx.src, re.M):
        (groups["stdlib"] if m.group(1) in stdlib
         else groups["third_party"]).add(m.group(1))
    return [Finding("dependencies", "imports", "INFO", 0,
                    "stdlib=%d third_party=%d"
                    % (len(groups["stdlib"]), len(groups["third_party"])),
                    metric={k: sorted(v) for k, v in groups.items()})]


# --- SCA
@analyzer("sca")
def sca(ctx):
    """Software-composition inventory: go.mod + Cargo.lock dependencies.
    Offline mode: inventory + manifest-adjacency findings.  Severity INFO;
    OSV/CVE matching plugs in behind the same Finding shape."""
    out = []
    go_mod = ctx.path.parent / "go.mod"
    if go_mod.exists():
        go_src = go_mod.read_text(encoding="utf-8")
        for ln in go_src.splitlines():
            m = re.match(r"^\s*(require\s+)?([\w.~/-]+)\s+v([\w.+-]+)", ln)
            if m and not ln.strip().startswith(("module", "go ")):
                out.append(Finding("sca", "go-dependency", "INFO",
                                   _line(go_src, go_src.find(ln)),
                                   f"{m.group(2)} v{m.group(3)}",
                                   fix="check against OSV"))
    lock = ctx.path.parent / "package-lock.json"
    if lock.exists():
        import json as _json
        data = _json.loads(lock.read_text(encoding="utf-8"))
        for name, meta in (data.get("packages") or {}).items():
            if name.startswith("node_modules/"):
                out.append(Finding("sca", "npm-dependency", "INFO", 0,
                                   f"{name[13:]} v{meta.get('version', '?')}",
                                   fix="check against OSV"))
    cargo = ctx.path.parent / "Cargo.lock"
    if cargo.exists():
        for m in re.finditer(r'name = "([\w-]+)"\nversion = "([\w.+-]+)"',
                             cargo.read_text(encoding="utf-8")):
            out.append(Finding("sca", "crate-dependency", "INFO", 0,
                               f"{m.group(1)} v{m.group(2)}",
                               fix="check against OSV"))
    return out
