"""
zk - under-constrained circuit detection

Circom subset parser: signal declarations, '<==' (assignment + constraint),
'<--' (assignment without constraint -- the classic under-constrained bug),
'===' constraints. A circuit is constrained iff every output signal appears
in at least one '===' constraint. '<--' assignments are flagged unless a
matching '===' covers their target. Findings name the signal and the kind;
absence of findings is never silently called "secure"."""

from __future__ import annotations

import re


class CircomError(ValueError):
    pass


_SIGNAL = re.compile(r"signal\s+(input\s+|output\s+)?(\w+)")
_ASSIGN_C = re.compile(r"(\w+)\s*<==\s*(.+);")
_ASSIGN_U = re.compile(r"(\w+)\s*<--\s*(.+);")
_CONSTR = re.compile(r"(.+)\s*===\s*(.+);")


def audit_circuit(src):
    """Under-constrained-circuit audit for the Circom subset."""
    outputs, inputs = set(), set()
    constrained_vars = set()
    assign_c, assign_u = [], []
    for raw in src.splitlines():
        line = raw.split("//")[0].strip()
        if not line:
            continue
        m = _SIGNAL.search(line)
        if m:
            kind, name = m.group(1), m.group(2)
            (inputs if kind and "input" in kind else
             outputs if kind and "output" in kind else set()).add(name) \
                if kind else None
            if not kind:     # intermediate
                pass
            continue
        m = _CONSTR.match(line)
        if m:
            for v in re.findall(r"\b\w+\b", m.group(1) + " " + m.group(2)):
                constrained_vars.add(v)
            continue
        m = _ASSIGN_C.match(line)
        if m:
            assign_c.append((m.group(1), m.group(2)))
            for v in re.findall(r"\b\w+\b", m.group(1) + " " + m.group(2)):
                constrained_vars.add(v)
            continue
        m = _ASSIGN_U.match(line)
        if m:
            assign_u.append((m.group(1), m.group(2)))
            continue
        if line.startswith(("template", "component", "}", "{", "pragma",
                            "include")):
            continue
        raise CircomError(f"zk: unsupported line {line!r}")
    findings = []
    for tgt, _ in assign_u:
        if tgt not in constrained_vars:
            findings.append({"signal": tgt,
                             "kind": "unconstrained-assignment",
                             "detail": "'<--' assigns without a constraint -- "
                                       "the classic under-constrained bug"})
    for out in outputs:
        if out not in constrained_vars:
            findings.append({"signal": out,
                             "kind": "unconstrained-output",
                             "detail": "output appears in no '===' constraint"})
    return {"findings": findings, "constrained": not findings,
            "note": "clean report covers the parsed subset only"}


def is_mock_check(findings):
    return findings
