"""
autopilot — compliance evidence autopilot

One interactive, signed HTML evidence report for a source tree.
Per .* file: GDPR taint findings (pegrex.compliance), cognitive
complexity (pegrex.cognitive), and path contracts (pegrex.api) --
refusals are RECORDED AS FINDINGS, never fatal, never silent. Repo
level: contract-deadline summary (pegrex.legalci) over any LEGAL* /
*.legal.* text files in the tree. The whole findings document is
HMAC-signed (pegrex.attest) and its canonical JSON + signature +
sha256 are embedded in the report itself, so the evidence is
self-authenticating. An empty tree is a loud AutopilotError -- an
"everything is fine" report about nothing is refused, not emitted."""

from __future__ import annotations

import hashlib
import html
import json
import pathlib

from .attest import canonical_json, hmac_sign
from .cognitive import cognitive_complexity
from .compliance import ComplianceError, audit_gdpr
from .export import to_html
from .legalci import ci_report

COGNITIVE_BUDGET = 7
SKIP_DIRS = {".pegrex-cache", "__pycache__"}


class AutopilotError(ValueError):
    """Loud refusal from the autopilot -- never an empty evidence report."""


def _iter_py(root):
    root = pathlib.Path(root)
    for p in sorted(root.rglob("*.py")):
        if any(part in SKIP_DIRS for part in p.relative_to(root).parts):
            continue
        yield p


def _legal_texts(root):
    """Contract/legal text sources for the legalci deadline summary:
    files named LEGAL.* / CLAUSES.* at any depth, or *.legal.txt /
    *.legal.md. Nothing found -> empty deadline list (stated, not faked)."""
    root = pathlib.Path(root)
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        n = p.name.lower()
        if (n.startswith("legal.") or n.startswith("clauses.")
                or n.endswith(".legal.txt") or n.endswith(".legal.md")):
            yield p


def _audit_file(root, path) -> list:
    rel = path.relative_to(root).as_posix()
    src = path.read_text(encoding="utf-8")
    findings = []
    # GDPR taint: unsupported statements refuse -> recorded finding
    try:
        for f in audit_gdpr(src):
            findings.append({
                "category": "gdpr", "kind": f["kind"], "file": rel,
                "line": "",
                "detail": f"{rel}: {f['detail']} (sink {f.get('sink')}, "
                          f"flow {f.get('flow')})"})
    except ComplianceError as e:
        findings.append({"category": "gdpr", "kind": "audit-refused",
                         "file": rel, "line": "",
                         "detail": f"{rel}: audit_gdpr refused: {e}"})
    # cognitive complexity: three-valued, syntax errors recorded
    cog = cognitive_complexity(src, budget=COGNITIVE_BUDGET)
    if cog.get("verdict") == "unknown":
        findings.append({"category": "cognitive", "kind": "audit-unknown",
                         "file": rel, "line": "",
                         "detail": f"{rel}: cognitive complexity UNKNOWN: "
                                   f"{cog.get('reason')}"})
    else:
        for fn in cog.get("functions", []):
            if fn["complexity"] > COGNITIVE_BUDGET:
                findings.append({
                    "category": "cognitive", "kind": "cognitive-over-budget",
                    "file": rel, "line": fn["line_start"],
                    "detail": f"{rel}: function {fn['name']!r} cognitive "
                              f"complexity {fn['complexity']} exceeds the "
                              f"budget {COGNITIVE_BUDGET}"})
    # path contracts: extraction refusals recorded, never fatal
    from . import api
    try:
        cons = api.contracts(str(path))
        if cons:
            findings.append({
                "category": "contract", "kind": "contracts-extracted",
                "file": rel, "line": "",
                "detail": f"{rel}: {len(cons)} path contract(s) extracted "
                          f"by the engine (analysis only; see each tool's "
                          f"own scope for what they cover)"})
        else:
            findings.append({"category": "contract", "kind": "contracts-empty",
                             "file": rel, "line": "",
                             "detail": f"{rel}: no executable paths "
                                       f"extracted"})
    except Exception as e:
        findings.append({"category": "contract", "kind": "audit-refused",
                         "file": rel, "line": "",
                         "detail": f"{rel}: contract extraction refused: "
                                   f"{type(e).__name__}: {str(e)[:140]}"})
    return findings


def _deadlines(root) -> list:
    rows = []
    for p in _legal_texts(root):
        try:
            rep = ci_report(p.read_text(encoding="utf-8"))
        except Exception as e:
            rows.append({"file": p.relative_to(root).as_posix(),
                         "status": "refused", "reason": str(e)[:120]})
            continue
        for row in rep["clauses"]:
            rows.append({"file": p.relative_to(root).as_posix(), **row})
    return rows


_FILTER_SCRIPT = (
    "<script>"
    "function pegrexFilter(cat){"
    "var rows=document.querySelectorAll('#pegrex-findings tr');"
    "for(var i=1;i<rows.length;i++){"
    "var c=rows[i].cells[0].textContent;"
    "rows[i].style.display=(cat==='all'||c===cat)?'':'none';}}"
    "</script>")


def _render_html(title, findings, by_category, envelope) -> str:
    table_rows = [{"severity": f["category"], "id": f["kind"],
                   "line": f.get("line", ""), "evidence": f["detail"][:200]}
                  for f in findings]
    page = to_html(table_rows, title=title).replace(
        "<table>", '<table id="pegrex-findings">', 1)
    cats = sorted(by_category)
    buttons = "".join(
        f"<button type='button' onclick=\"pegrexFilter('{c}')\">{c} "
        f"({by_category[c]})</button>" for c in cats)
    buttons += ("<button type='button' "
                "onclick=\"pegrexFilter('all')\">all</button>")
    bar = f"<div id='pegrex-filter'>{buttons}</div>"
    # the machine-readable envelope: "<" escaped so it survives inside a
    # <script> element; json.loads reverses it exactly.
    embed = json.dumps(envelope, sort_keys=True).replace("<", "\\u003c")
    machine = (f"<script type='application/json' id='pegrex-manifest'>"
               f"{embed}</script>")
    pretty = html.escape(json.dumps(envelope, indent=1, sort_keys=True))
    human = (f"<details id='signed-manifest'><summary>signed manifest "
             f"(HMAC-SHA256; sha256 {envelope['manifest_sha256'][:16]}&hellip;)"
             f"</summary>"
             f"<p>manifest sha256: <code>{envelope['manifest_sha256']}</code></p>"
             f"<p>signature: <code>{envelope['signature']}</code></p>"
             f"<pre>{pretty}</pre></details>")
    return f"{page}{bar}{_FILTER_SCRIPT}{machine}{human}"


def build_report(root, out_html, key, title="pegrex evidence report") -> dict:
    """Walk `root` for .* files (skipping .pegrex-cache / __pycache__;
    tests included -- honest evidence skips nothing else), audit each,
    summarize legal deadlines, sign the findings, and emit ONE
    self-contained interactive HTML report.

    Returns {"out", "files", "findings", "by_category", "deadlines",
    "manifest_sha256", "ok"}. An empty tree is a loud AutopilotError --
    refusing to emit an empty evidence report."""
    root = pathlib.Path(root)
    py_files = list(_iter_py(root))
    if not py_files:
        raise AutopilotError(
            f"autopilot: nothing to audit under {root} (no .py files) -- "
            f"refusing to emit an empty evidence report")
    findings = []
    for p in py_files:
        findings.extend(_audit_file(root, p))
    deadlines = _deadlines(root)
    by_category = {}
    for f in findings:
        by_category[f["category"]] = by_category.get(f["category"], 0) + 1
    manifest = {"title": title, "root": str(root),
                "files": [p.relative_to(root).as_posix() for p in py_files],
                "findings": findings, "by_category": by_category,
                "deadlines": deadlines, "generator": "pegrex.autopilot"}
    signature = hmac_sign(manifest, key)
    manifest_sha256 = hashlib.sha256(
        canonical_json(manifest).encode()).hexdigest()
    envelope = {"manifest": manifest, "signature": signature,
                "manifest_sha256": manifest_sha256}
    html_text = _render_html(title, findings, by_category, envelope)
    pathlib.Path(out_html).write_text(html_text, encoding="utf-8")
    return {"out": str(out_html), "files": len(py_files),
            "findings": len(findings), "by_category": by_category,
            "deadlines": deadlines, "manifest_sha256": manifest_sha256,
            "ok": True}


def verify_report(html_text, key) -> dict:
    """Re-authenticate an emitted report: extract the embedded envelope,
    re-hash the manifest, and check the HMAC signature."""
    from .attest import hmac_verify
    start = html_text.find('id=\'pegrex-manifest\'>')
    if start < 0:
        return {"ok": False, "reason": "no embedded manifest in report"}
    start = html_text.find(">", start) + 1
    end = html_text.find("</script>", start)
    try:
        envelope = json.loads(html_text[start:end])
    except ValueError as e:
        return {"ok": False, "reason": f"embedded manifest unreadable: {e}"}
    manifest = envelope.get("manifest")
    sha = hashlib.sha256(canonical_json(manifest).encode()).hexdigest()
    if sha != envelope.get("manifest_sha256"):
        return {"ok": False, "reason": "manifest sha256 mismatch -- the "
                                         "findings were altered"}
    if not hmac_verify(manifest, key, envelope.get("signature")):
        return {"ok": False, "reason": "signature mismatch (tampered or "
                                         "wrong key)"}
    return {"ok": True, "files": len(manifest.get("files", [])),
            "findings": len(manifest.get("findings", [])),
            "manifest_sha256": sha}
