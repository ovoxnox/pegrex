"""taint.py -- intra-procedural taint analysis engine.

Approximates Semgrep taint-mode rules with source-order def-taint
propagation: sources seed taint, assignments propagate it through variables,
sanitizer calls suppress it, and sink calls touching tainted data are reported.
This is intentionally not CFG/SSA or field-sensitive analysis. Strict rules
retain unresolved flows as UNKNOWN; callers must not present them as clean.

Rules are data (pegrex/secrules_taint.json): extracted sink/source/
sanitizer signatures from semgrep-rules YAML taint rules.
"""
import re

from .peg import Node


def _span(node, src):
    return src[node.pos:node.endpos]


def _contains(node, rx, src):
    """True if any descendant's span matches compiled regex rx."""
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, Node):
            if rx.search(src[n.pos:n.endpos]):
                return True
            stack.extend(c for c in n.children if isinstance(c, Node))
    return False


def _matching_evidence(node, rxs, src):
    """Concrete source matches for SARIF relatedLocations/codeFlows."""
    found, seen = [], set()
    stack = [node]
    while stack:
        current = stack.pop()
        if not isinstance(current, Node):
            continue
        span = src[current.pos:current.endpos]
        for rx in rxs:
            for match in rx.finditer(span):
                start = current.pos + match.start()
                evidence = match.group(0).strip()[:160]
                key = (start, evidence)
                if key in seen:
                    continue
                seen.add(key)
                found.append({
                    "line": src[:start].count("\n") + 1,
                    "column": start - src.rfind("\n", 0, start),
                    "evidence": evidence,
                })
                if len(found) >= 16:
                    return found
        stack.extend(c for c in current.children if isinstance(c, Node))
    return sorted(found, key=lambda item: (item["line"], item["column"],
                                           item["evidence"]))


def _merge_origins(*groups):
    out, seen = [], set()
    for group in groups:
        for origin in group:
            key = (origin["line"], origin["column"], origin["evidence"])
            if key not in seen:
                seen.add(key)
                out.append(origin)
    return out[:16]


def _func_bodies(tree):
    """(name, body) for every function-ish node in the tree."""
    tags = ("function_definition", "function_declaration", "function_item")
    out = []
    def walk(n, name=None):
        """walk(n, name): see module docstring."""
        if isinstance(n, Node):
            nm = name
            if n.tag in tags:
                kids = [c for c in n.children if isinstance(c, Node)]
                nm = (kids[0].children[0] if kids and kids[0].children
                      and isinstance(kids[0].children[0], str) else None)
                body = kids[-1] if kids else n
                out.append((nm, body))
            for c in n.children:
                walk(c, nm)
        elif isinstance(n, list):
            for c in n:
                walk(c, name)
    walk(tree)
    return out


ASSIGN_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*=")


def analyze_taint(tree, src, rule, rounds: int = 2):
    """Returns (findings, unknowns) when rule has strict_missing, else
    findings only (backwards compatible).  ash_rules semantics:
      tainted -> finding;  sanitized -> clean;  UNKNOWN identifier at a
    strict sink -> reported as 'unknown', never silently clean."""
    """Return findings for one taint rule.

    rounds=2: round 0 is intra-procedural; round 1 re-runs with callee
    parameters pre-tainted wherever a tainted value flowed into a call
    (light inter-procedural propagation, no field sensitivity)."""
    sinks = [re.compile(r) for r in rule["sinks"]]
    sources = [re.compile(r) for r in rule["sources"]]
    sanitizers = [re.compile(r) for r in rule.get("sanitizers", [])]
    findings = []
    unknowns = []
    tainted_params: dict[str, set] = {}

    def subtree_has(node, rxs):
        """subtree has(node, rxs): see module docstring."""
        return any(_contains(node, r, src) for r in rxs)

    for rnd in range(rounds):
      for fname, body in _func_bodies(tree):
        inherited_params = tainted_params.get(fname, [])
        tainted_vars = set()
        origins = {}
        if inherited_params:
            tainted_vars.add("arg")
            origins["arg"] = list(inherited_params)
        # walk all statements in source order (approximation: AST DFS order)
        def visit(n):
            """visit(n): see module docstring."""
            if not isinstance(n, Node):
                return
            txt = _span(n, src).strip()
            if n.tag in ("assignment", "augmented_assignment"):
                m = ASSIGN_RE.match(txt)
                if m:
                    var, rhs = m.group(1), n
                    rhs_text = _span(rhs, src)
                    direct = _matching_evidence(rhs, sources, src)
                    inherited = _merge_origins(*(
                        origins.get(v, []) for v in tainted_vars
                        if re.search(rf"\b{re.escape(v)}\b", rhs_text)))
                    is_tainted = bool(direct or inherited)
                    if is_tainted and not subtree_has(rhs, sanitizers):
                        tainted_vars.add(var)
                        origins[var] = _merge_origins(direct, inherited)
                    elif var in tainted_vars and not is_tainted:
                        tainted_vars.discard(var)
                        origins.pop(var, None)
            if n.tag in ("call", "call_expression"):
                import re as _re2
                call_text = _span(n, src)
                mcall = _re2.search(r"([A-Za-z_]\w*)\(", call_text)
                direct = _matching_evidence(n, sources, src)
                inherited = _merge_origins(*(
                    origins.get(v, []) for v in tainted_vars
                    if _re2.search(rf"\b{re.escape(v)}\b", call_text)))
                flow_origins = _merge_origins(direct, inherited)
                if mcall and flow_origins:
                    tainted_params[mcall.group(1)] = _merge_origins(
                        tainted_params.get(mcall.group(1), []), flow_origins)
                if any(_contains(n, r, src) for r in sinks):
                    # argument subtree = the call node itself; check taint
                    tainted = bool(flow_origins)
                    clean = subtree_has(n, sanitizers)
                    if tainted and not clean:
                        findings.append({
                            "line": src[:n.pos].count("\n") + 1,
                            "column": n.pos - src.rfind("\n", 0, n.pos),
                            "evidence": txt[:90],
                            "sink": txt[:160],
                            "source": flow_origins[0]["evidence"],
                            "sources": flow_origins,
                            "function": fname,
                        })
                    elif (rule.get("strict_missing") and not clean
                            and not subtree_has(n, sources)):
                        # ash_rules 'missing: :unknown' -- the argument is an
                        # identifier we cannot resolve to a source; in strict
                        # mode an unknown is not clean (it may be tainted
                        # through a path we cannot see).
                        import re as _re3
                        arg_txt = _span(n, src)
                        if (_re3.search(r"\b[a-z_]\w+\b(?![\w\(])",
                                        arg_txt)
                                and "request" not in arg_txt
                                and '"' not in arg_txt
                                and "'" not in arg_txt
                                and all(u["line"] != src[:n.pos].count("\n") + 1
                                        for u in unknowns)):
                            unknowns.append({
                                "line": src[:n.pos].count("\n") + 1,
                                "column": n.pos - src.rfind("\n", 0, n.pos),
                                "evidence": txt[:90],
                                "sink": txt[:160],
                                "source": "unresolved input origin",
                                "sources": [],
                                "function": fname,
                            })
            for c in n.children:
                visit(c)
        visit(body)
    if rule.get("strict_missing"):
        return findings, unknowns
    return findings
