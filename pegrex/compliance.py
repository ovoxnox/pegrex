"""
compliance - legal and compliance as code

GDPR data-flow constraints via taint: PII sources ('# pii: NAME'),
sinks ('# sink: NAME [needs consent]'), and consent sanitizers
('# consent: fn'). A flow from PII to a consent-gated sink without the
consent call on the path is a finding that names the flow -- never a
shrug, never compliance-by-absence. SOC2-style control presence checks
are included (required call must appear on PII-handling paths).
"""
from __future__ import annotations

import re


class ComplianceError(ValueError):
    pass


from .annotations import annotations as _read_annotations


def _scan_annotations(src, lang):
    ann = _read_annotations(src, lang)
    pii = set(ann.get("pii", []))
    sinks = {s.split()[0]: ("needs" in s) for s in ann.get("sink", [])}
    return pii, sinks, set(ann.get("consent", []))
_ASSIGN_RX = re.compile(r"^(\w+)\s*(:=|=)\s*(.+)$")
_CALL_RX = re.compile(r"^(\w+)\s*\((.*)\)$")
_IF_RX = re.compile(r"^if\s+(.+):$")


def audit_gdpr(src, lang="python"):
    """Findings: PII flows to consent-gated sinks without consent."""
    pii, sinks, consent_fns = _scan_annotations(src, lang)
    from .annotations import comment_prefix
    prefix = comment_prefix(lang)
    body = []
    for raw in src.splitlines():
        s = raw.strip()
        if s and not s.startswith(prefix):
            body.append(s)
    findings = []
    taint = set()  # currently-tainted names (path-sensitive walk)
    consent_seen = set()

    def walk(stmts, tainted, seen):
        """Implement walk with the module's explicit API and failure semantics."""
        i = 0
        while i < len(stmts):
            s = stmts[i].strip()
            m = _IF_RX.match(s)
            if m:
                # find the indented block (next lines starting with spaces)
                j = i + 1
                block = []
                while j < len(stmts) and stmts[j].startswith((" ", "\t")):
                    block.append(stmts[j].strip())
                    j += 1
                walk(block, set(tainted), set(seen))
                i = j
                continue
            if s.startswith(("def ", "return", "elif", "else")):
                i += 1
                continue
            if s in ("{", "}", ");", "") or s == "}":
                i += 1
                continue
            if re.match(r"^(func|function|fn|fun|class|contract|package)\b.*\{?$",
                         s):
                i += 1
                continue
            if re.match(r"^(if|while|for)\b.*\{?$", s) and not _IF_RX.match(s):
                if re.match(r"^(if|while)\b", s):
                    guard = re.sub(r"^(if|while)\s*\(?\s*|\s*\{?\s*$", "", s)
                    j2 = i + 1
                    block = []
                    depth = 1
                    while j2 < len(stmts) and depth > 0:
                        s2 = stmts[j2].strip()
                        depth += s2.count("{") - s2.count("}")
                        if depth > 0:
                            block.append(stmts[j2])
                        j2 += 1
                    walk(block, set(tainted), set(seen))
                    i = j2
                    continue
                i += 1
                continue
            m = re.match(r"^(while|for)\s+(.+):$", s)
            if m:
                # loops: taint flows in; no guard precision claimed (the
                # facts stay sound via over-approximation, documented)
                j = i + 1
                block = []
                while j < len(stmts) and stmts[j].startswith((" ", "\t")):
                    block.append(stmts[j])
                    j += 1
                walk(block, set(tainted), set(seen))
                i = j
                continue
            m = _ASSIGN_RX.match(s)
            if m:
                dst = m.group(1)
                rhs = m.group(3) if m.group(3) is not None else m.group(2)
                names = set(re.findall(r"\b\w+\b", rhs))
                cm = _CALL_RX.match(rhs.strip())
                if cm and cm.group(1) in consent_fns:
                    seen.add(cm.group(1))  # consent may sit in assignment
                if names & tainted or names & pii:
                    tainted.add(dst)
                else:
                    tainted.discard(dst)
                i += 1
                continue
            m = _CALL_RX.match(s)
            if m:
                fn = m.group(1)
                args = set(re.findall(r"\b\w+\b", m.group(2)))
                if fn in consent_fns:
                    seen.add(fn)
                if fn in sinks and sinks[fn] and (args & (tainted | pii)):
                    if not (set(consent_fns) & seen):
                        findings.append({"kind": "gdpr-no-consent",
                                         "sink": fn,
                                         "flow": sorted(args & tainted),
                                         "detail": "PII reaches a "
                                                   "consent-gated sink without "
                                                   "a consent call on this path"})
                i += 1
                continue
            raise ComplianceError(f"compliance: unsupported statement {s!r}")
    raw = [l for l in src.splitlines()
           if l.strip() and not l.strip().startswith(prefix)]
    indents = [len(l) - len(l.lstrip()) for l in raw
               if not l.lstrip().startswith(("def ", "return", "elif", "else"))]
    base = min(indents) if indents else 0
    def strip(l):
        """Implement strip with the module's explicit API and failure semantics."""
        return l[base:] if l[:base].strip() == "" else l   # only ws prefix
    normalized = [strip(l) for l in raw]
    walk(normalized, set(), set())
    return findings


def audit_soc2(src, controls, lang="python"):
    """Each control: {'id', 'require': regex, 'on': 'pii-paths'|'always'}.
    Missing required patterns on PII-handling sources are findings."""
    findings = []
    has_pii = bool(_scan_annotations(src, lang)[0])
    for c in controls:
        if c.get("on", "always") == "pii-paths" and not has_pii:
            continue
        if not re.search(c["require"], src):
            findings.append({"kind": "soc2-missing-control",
                             "control": c["id"],
                             "detail": f"required pattern absent: {c['require']}"})
    return findings
