"""
parallel.py -- OpenMP / PyOMP support: pragma recognition, parallel-region
annotation, and a shared-write data-race heuristic.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

OMP_RE = re.compile(
    r"#\$\s*omp\s+(parallel|for|critical|atomic|barrier)"
    r"|#pragma\s+omp\s+(parallel|for|critical|atomic|barrier)")
ASSIGN_RE = re.compile(r"^\s*(?:[\w*<>,]+\s+)?([A-Za-z_]\w*)\s*(?:\+=|-=|\*=|/=|=)")


@dataclass
class ParallelRegion:
    """ParallelRegion - see module docstring."""
    line: int
    kind: str             # parallel | for | critical | atomic | barrier
    writes: list = field(default_factory=list)
    synced: bool = False  # critical/atomic/barrier present


def find_pragmas(src: str) -> list[ParallelRegion]:
    """OMP/PyOMP pragma lines -> region descriptors (line, kind)."""
    out = []
    for i, ln in enumerate(src.splitlines(), 1):
        m = OMP_RE.search(ln)
        if m:
            kind = next(g for g in m.groups() if g)
            out.append(ParallelRegion(i, kind))
    return out


def race_findings(src: str, window: int = 12) -> list[str]:
    """Shared-write heuristic: a 'parallel' region that writes a variable
    declared outside the region, without critical/atomic/barrier -> race.
    A single shared write is enough: N threads write it concurrently."""
    regions = find_pragmas(src)
    lines = src.splitlines()
    findings = []
    for r in regions:
        if r.kind != "parallel":
            continue
        outer = set()
        for j in range(max(0, r.line - window), r.line):
            m = ASSIGN_RE.match(lines[j])
            if m:
                outer.add(m.group(1))
        synced = False
        inner_writes = set()
        for j in range(r.line, min(r.line + window, len(lines))):
            m = ASSIGN_RE.match(lines[j])
            if m:
                inner_writes.add(m.group(1))
            if OMP_RE.search(lines[j]) and any(
                    k in lines[j] for k in ("critical", "atomic", "barrier")):
                synced = True
        if not synced:
            shared = inner_writes & outer
            for v in sorted(shared):
                findings.append(f"possible data race on '{v}' "
                                f"(parallel region at line {r.line}, "
                                f"shared write, no synchronization)")
    return findings
