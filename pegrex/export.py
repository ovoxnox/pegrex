"""export -- multi-format reporting (JSON / CSV / HTML)"""

from __future__ import annotations

import csv
import json
import html
import io
import json


def to_csv(findings: list) -> str:
    """to csv(findings): see module docstring."""
    buf = io.StringIO()
    if not findings:
        return ""
    w = csv.DictWriter(buf, fieldnames=sorted(findings[0].keys()),
                       extrasaction="ignore")
    w.writeheader()
    w.writerows(findings)
    return buf.getvalue()


def to_html(findings: list, title: str = "pegrex report") -> str:
    """Cyberpunk HTML report. All finding text is html-escaped (XSS-safe); 
    grouping is by severity, with an everything-raw JSON expander at the bottom."""
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    sev_color = {"CRITICAL": "#ff2d55", "HIGH": "#ff6b35", "MEDIUM": "#ffb300",
                 "LOW": "#00f0ff", "INFO": "#8b949e"}

    def sev(f):
        return str(f.get("severity", "INFO")).upper()

    def ev(f):
        return html.escape(str(f.get("evidence", f.get("message", ""))))

    def fid(f):
        return html.escape(str(f.get("id", "")))

    groups = {s: [] for s in sev_order}
    for f in findings:
        groups.setdefault(sev(f), []).append(f)
    stats = "".join(
        "<span class=chip style=--c:" + sev_color.get(s, "#39ff14") + ">"
        + s + " <b>" + str(len(groups.get(s, []))) + "</b></span>"
        for s in sev_order if groups.get(s))

    def row(f):
        c = sev_color.get(sev(f), "#39ff14")
        line = f.get("line", "")
        return ("<details class=finding><summary>"
                "<span class=badge style=--c:" + c + ">" + sev(f) + "</span>"
                "<span class=rule>" + fid(f) + "</span>"
                "<span class=loc>L" + str(line) + "</span>"
                "<span class=chev>\u25b8</span></summary>"
                "<div class=ev>" + ev(f) + "</div></details>")

    def section(s):
        fs = groups.get(s, [])
        if not fs:
            return ""
        c = sev_color.get(s, "#39ff14")
        op = " open" if s in ("CRITICAL", "HIGH") else ""
        body = "".join(row(f) for f in fs)
        return ("<details class=sev" + op + ">"
                "<summary><span class=sevdot style=--c:" + c + "></span>"
                + s + " <b>" + str(len(fs)) + "</b></summary>" + body + "</details>")

    secs = "".join(section(s) for s in sev_order)
    raw = html.escape(json.dumps(findings, indent=1))
    when = __import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M")
    t = html.escape(title)
    return f"""<!doctype html>
<html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>{t}</title><style>
:root{{--bg:#04050d;--panel:rgba(13,17,38,.72);--edge:rgba(0,240,255,.22);
  --cyan:#00f0ff;--mag:#ff00a8;--grn:#39ff14;--dim:#7a86b8;--txt:#c9d4ff}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--txt);
  font:14px/1.55 "JetBrains Mono",ui-monospace,Menlo,Consolas,monospace;}}
body::before{{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background:repeating-linear-gradient(0deg,rgba(255,255,255,.028) 0 1px,transparent 1px 3px);}}
body::after{{content:"";position:fixed;inset:0;pointer-events:none;z-index:0;
  background:radial-gradient(60% 40% at 15% 0%,rgba(255,0,168,.10),transparent 60%),
  radial-gradient(50% 35% at 90% 10%,rgba(0,240,255,.10),transparent 60%);}}
.wrap{{position:relative;z-index:1;max-width:1040px;margin:0 auto;padding:34px 22px 60px}}
header.hero{{position:relative;padding:26px 26px 22px;border:1px solid var(--edge);
  background:linear-gradient(160deg,rgba(0,240,255,.06),rgba(255,0,168,.05) 60%,rgba(0,0,0,0));
  clip-path:polygon(0 0,calc(100% - 26px) 0,100% 26px,100% 100%,26px 100%,0 calc(100% - 26px));}}
h1{{margin:0;font-size:26px;letter-spacing:.14em;text-transform:uppercase;
  color:var(--cyan);text-shadow:0 0 18px rgba(0,240,255,.65),0 0 46px rgba(0,240,255,.30);}}
.sub{{color:var(--dim);margin-top:6px;letter-spacing:.06em}}
.stats{{display:flex;flex-wrap:wrap;gap:10px;margin:20px 0 8px}}
.chip{{--c:var(--cyan);border:1px solid color-mix(in srgb,var(--c) 45%,transparent);
  color:var(--c);background:color-mix(in srgb,var(--c) 9%,transparent);
  padding:4px 12px;border-radius:3px;letter-spacing:.08em;font-size:12px;
  text-shadow:0 0 10px var(--c);}}
.chip b{{margin-left:6px}}
details.sev{{margin:16px 0;border:1px solid var(--edge);background:var(--panel);
  backdrop-filter:blur(6px);border-radius:6px;overflow:hidden}}
details.sev>summary{{cursor:pointer;list-style:none;padding:12px 16px;
  letter-spacing:.12em;font-weight:700;display:flex;gap:10px;align-items:center;
  background:rgba(255,255,255,.02);}}
details.sev>summary::-webkit-details-marker{{display:none}}
details.sev>summary::after{{content:"\25b8";margin-left:auto;color:var(--dim);
  transition:transform .15s}}
details.sev[open]>summary::after{{transform:rotate(90deg)}}
.sevdot{{--c:var(--cyan);width:10px;height:10px;border-radius:50%;background:var(--c);
  box-shadow:0 0 12px var(--c)}}
details.finding{{border-top:1px solid rgba(255,255,255,.05)}}
details.finding>summary{{cursor:pointer;list-style:none;display:flex;gap:12px;
  align-items:center;padding:9px 16px}}
details.finding>summary::-webkit-details-marker{{display:none}}
details.finding>summary:hover{{background:rgba(0,240,255,.05)}}
.badge{{--c:var(--cyan);color:var(--c);border:1px solid color-mix(in srgb,var(--c) 55%,transparent);
  padding:1px 8px;font-size:11px;border-radius:2px;letter-spacing:.1em;
  text-shadow:0 0 8px var(--c);min-width:76px;text-align:center}}
.rule{{color:var(--txt)}}
.loc{{color:var(--dim);font-size:12px}}
.chev{{margin-left:auto;color:var(--dim)}}
details.finding .ev{{padding:4px 18px 14px 116px;color:#a9b6e8;white-space:pre-wrap;
  font-size:13px;border-left:2px solid rgba(0,240,255,.25);margin:0 16px 12px;}}
details.raw pre{{max-height:340px;overflow:auto;background:rgba(0,0,0,.45);
  border:1px solid var(--edge);padding:14px;border-radius:6px;font-size:12px}}
footer{{margin-top:34px;color:var(--dim);font-size:12px;letter-spacing:.08em;
  display:flex;justify-content:space-between;border-top:1px solid rgba(255,255,255,.06);
  padding-top:14px}}
</style></head><body><div class=wrap>
<header class=hero><h1>{t}</h1>
<div class=sub>pegrex security export -- {len(findings)} finding(s) -- {when}</div>
<div class=stats>{stats}</div></header>
{secs}
<details class="sev raw"><summary><span class=sevdot style=--c:#8b949e></span>
RAW JSON</summary><pre>{raw}</pre></details>
<footer><span>PEGREX // EXPORT MODULE</span><span>PROOF &gt; PROMISE</span></footer>
</div></body></html>"""

def export(findings: list, fmt: str, out: str | None = None,
           title: str = "pegrex report") -> str:
    """export(findings, fmt, out, title): see module docstring."""
    text = (json.dumps(findings, indent=1) if fmt == "json"
            else to_csv(findings) if fmt == "csv"
            else to_html(findings, title))
    if out:
        import pathlib
        pathlib.Path(out).write_text(text)
    return text


def to_sarif(findings: list, tool: str = "pegrex") -> str:
    """SARIF 2.1.0 for GitHub code scanning integration."""
    rules, results = {}, []
    for i, f in enumerate(findings):
        rid = f.get("id", f"rule-{i}")
        rules.setdefault(rid, {"id": rid, "name": rid,
                               "shortDescription": {"text": f.get("message", rid)[:120]}})
        results.append({"ruleId": rid,
                        "level": {"CRITICAL": "error", "HIGH": "error",
                                  "MEDIUM": "warning"}.get(f.get("severity"), "note"),
                        "message": {"text": f.get("evidence", f.get("message", ""))[:200]},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": f.get("file", "")},
                            "region": {"startLine": max(1, f.get("line", 1))}}}]})
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
           "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": tool,
                                         "rules": list(rules.values())}},
                     "results": results}]}
    return json.dumps(doc, indent=1)


export.__globals__["to_sarif"] = to_sarif
