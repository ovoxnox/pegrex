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


def _terraform_resources(src: str):
    """Extract a conservative subset of Terraform resource blocks by brace depth."""
    header = re.compile(r'\bresource\s+"([^"\n]+)"\s+"([^"\n]+)"\s*\{')
    for match in header.finditer(src):
        start = match.end()
        depth, quoted, escaped = 1, False, False
        index = start
        while index < len(src) and depth:
            char = src[index]
            if quoted:
                if escaped: escaped = False
                elif char == "\\": escaped = True
                elif char == '"': quoted = False
            else:
                if char == '"': quoted = True
                elif char == "{": depth += 1
                elif char == "}": depth -= 1
            index += 1
        if depth == 0:
            yield match.group(1), match.group(2), src[start:index - 1]


def audit_terraform(src):
    """Find findings in a bounded, brace-aware Terraform resource subset.

    Absence of a finding is not proof of secure configuration: modules, variables,
    provider defaults, dynamic blocks, remote state and inherited policies are not
    fully evaluated.
    """
    findings = []
    resources = list(_terraform_resources(src))
    for resource_type, name, body in resources:
        identity = f"{resource_type}.{name}"
        if resource_type == "aws_s3_bucket" and _TF_PUBLIC.search(body):
            findings.append({"kind": "s3-public-read", "resource": identity,
                             "detail": 'acl = "public-read" exposes the bucket'})
        if resource_type == "aws_s3_bucket_public_access_block":
            disabled = [key for key in ("block_public_acls", "block_public_policy",
                                         "ignore_public_acls", "restrict_public_buckets")
                        if re.search(rf"\b{key}\s*=\s*false\b", body, re.I)]
            if disabled:
                findings.append({"kind": "s3-public-access-block-disabled", "resource": identity,
                                 "detail": "public access block controls disabled: " + ", ".join(disabled)})
        if resource_type in {"aws_db_instance", "aws_rds_cluster_instance"}:
            if re.search(r"\bpublicly_accessible\s*=\s*true\b", body, re.I):
                findings.append({"kind": "public-database", "resource": identity,
                                 "detail": "database is explicitly publicly accessible"})
            if re.search(r"\bstorage_encrypted\s*=\s*false\b", body, re.I):
                findings.append({"kind": "unencrypted-database", "resource": identity,
                                 "detail": "database storage encryption is explicitly disabled"})
        if resource_type in {"aws_security_group", "aws_security_group_rule"}:
            open_cidr = bool(re.search(r'cidr_blocks\s*=\s*\[[^]]*"0\.0\.0\.0/0"', body, re.I))
            protocol_all = bool(re.search(r'protocol\s*=\s*"-1"', body, re.I))
            ingress = bool(re.search(r'\btype\s*=\s*"ingress"', body, re.I))
            egress = bool(re.search(r'\btype\s*=\s*"egress"', body, re.I))
            ports = {int(x) for x in re.findall(r'\b(?:from_port|to_port)\s*=\s*(22|3389)\b', body)}
            if open_cidr and ingress and ports:
                findings.append({"kind": "public-admin-ingress", "resource": identity,
                                 "detail": "SSH/RDP ingress is open to 0.0.0.0/0", "ports": sorted(ports)})
            if open_cidr and egress and protocol_all:
                findings.append({"kind": "unrestricted-egress", "resource": identity,
                                 "detail": "all-protocol egress is open to 0.0.0.0/0"})
        if re.search(r'\b(?:password|client_secret|api_key|access_key)\s*=\s*"[^"$][^"\n]{7,}"', body, re.I):
            findings.append({"kind": "hardcoded-secret", "resource": identity,
                             "detail": "resource contains a literal credential-like value"})
    for match in re.finditer(r'Action\s*=\s*"\*"', src):
        findings.append({"kind": "terraform-wildcard-action",
                         "detail": 'Action = "*" in an allow rule',
                         "line": src.count("\n", 0, match.start()) + 1})
    # Stable de-duplication while retaining evidence/resource names.
    unique = {json.dumps(row, sort_keys=True): row for row in findings}
    return [unique[key] for key in sorted(unique)]

