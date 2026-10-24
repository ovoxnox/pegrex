"""
iac - infrastructure-as-code verification, Zelkova-style

IAM policy statements as allow/deny constraints: can(principal, action,
resource) answers via statement matching (effect, action globs, resource
globs). Terraform-flavoured checks: S3 public-read blocks, wildcard admin
grants (Action:* with Resource:*). Verdicts are findings lists; 'no
findings' covers exactly what was parsed -- nothing more.
"""

from __future__ import annotations

import fnmatch
import json
import re


def _globs(patterns):
    return [p for p in (patterns if isinstance(patterns, list)
                        else [patterns])]


def can(statements, action, resource):
    """Zelkova-style: decide allow/deny from IAM-style statements."""
    allow = False
    for st in statements:
        acts = _globs(st.get("Action", []))
        res = _globs(st.get("Resource", []))
        act_ok = any(fnmatch.fnmatchcase(action, a) for a in acts)
        res_ok = any(fnmatch.fnmatchcase(resource, r) for r in res)
        if act_ok and res_ok:
            if st.get("Effect") == "Deny":
                return "deny"  # explicit deny wins
            allow = True
    return "allow" if allow else "deny"


def audit_policy(doc):
    """Findings over an IAM policy document (dict or JSON string)."""
    if isinstance(doc, str):
        doc = json.loads(doc)
    findings = []
    for st in doc.get("Statement", []):
        acts = _globs(st.get("Action", []))
        res = _globs(st.get("Resource", []))
        if st.get("Effect") == "Allow" and "*" in acts and "*" in res:
            findings.append({"kind": "wildcard-admin",
                             "detail": "Allow * on * is full administrative "
                                       "access"})
        if st.get("Effect") == "Allow" and any(a == "s3:*" for a in acts):
            findings.append({"kind": "s3-full-control",
                             "detail": "s3:* grants full bucket control"})
    return findings


_TF_PUBLIC = re.compile(r'acl\s*=\s*"public-read"', re.I)
_TF_WILDCARD_ACTION = re.compile(r'action\s*=\s*"\*"', re.I)


def audit_terraform(src):
    """Terraform-flavoured checks for the audited subset."""
    findings = []
    if _TF_PUBLIC.search(src):
        findings.append({"kind": "s3-public-read",
                         "detail": 'acl = "public-read" exposes the bucket'})
    for m in re.finditer(r"Action\s*=\s*\"\*\"", src):
        findings.append({"kind": "terraform-wildcard-action",
                         "detail": 'Action = "*" in an allow rule'})
    return findings
