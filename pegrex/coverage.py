"""
coverage 

Constraint-aware path coverage: LCOV + Go coverprofile in, path
coverage out. Not "line 42 uncovered" but "no test satisfies
(n < 0) on path 1 — add a test with n=-1". 

The formulas make gaps actionable."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class CoverLine:
    line: int
    hits: int


def parse_lcov(text: str) -> dict[str, list[CoverLine]]:
    """LCOV tracefile -> {source_path: [CoverLine]}.  Universal: Rust
    (grcov/llvm-cov), JS (nyc/c8), C (gcov) all export it."""
    out: dict[str, list[CoverLine]] = {}
    cur = None
    for ln in text.splitlines():
        if ln.startswith("SF:"):
            cur = ln[3:]
            out[cur] = []
        elif ln.startswith("DA:") and cur is not None:
            line, _, hits = ln[3:].partition(",")
            out[cur].append(CoverLine(int(line), int(hits or 0)))
    return out


def parse_gocover(text: str) -> list[CoverLine]:
    """Go -coverprofile -> [CoverLine] (start-line granularity)."""
    out = []
    for ln in text.splitlines()[1:]:          # skip 'mode:' header
        m = re.match(r"[^:]++:(\d+)(?:\.\d+)?,(\d+)(?:\.\d+)? \d+ (\d+)", ln)
        if m:
            out.append(CoverLine(int(m.group(1)), int(m.group(3))))
    return out


def covered_lines(cov: list[CoverLine]) -> set[int]:
    """Implement covered lines with the module's explicit API and failure semantics."""
    return {c.line for c in cov if c.hits > 0}


def path_coverage(cfg, paths, cov_lines: set[int], pad: int = 0) -> list[dict]:
    """Overlay coverage onto enumerated paths via block->line mapping.

    Node spans carry byte offsets; the caller maps bytes to lines (or uses
    `lines_of` below when blocks hold statement nodes with positions in the
    same source).  A path is covered iff every block containing statements
    touches at least one covered line."""
    out = []
    for p in paths:
        blocks_with_stmts = [b for b in p
                             if cfg.blocks[b].stmts]
        if not blocks_with_stmts:
            out.append({"blocks": p, "covered": True, "reason": "no-stmt"})
            continue
        hit = 0
        for b in blocks_with_stmts:
            blk_lines = set()
            for st in cfg.blocks[b].stmts:
                for attr in ("pos", "start_line", "line"):
                    v = getattr(st, attr, None)
                    if isinstance(v, int):
                        blk_lines.add(v)
                        break
            if blk_lines & cov_lines:
                hit += 1
        out.append({"blocks": p, "covered": hit == len(blocks_with_stmts),
                    "hit_blocks": hit, "total_blocks": len(blocks_with_stmts)})
    return out


def coverage_gaps(cfg, cond, cov_lines: set[int], unroll: int = 2) -> list[dict]:
    """Satisfiable-but-uncovered paths, with their constraint context."""
    from pegrex.paths import PathEnumerator
    from pegrex.sym import Not
    gaps = []
    for p in PathEnumerator(cfg, unroll=unroll).enumerate():
        cons = []
        for i in range(len(p) - 1):
            for dst, e in cfg.successors(p[i]):
                if dst != p[i + 1] or e.cond is None:
                    continue
                if e.kind in ("then", "body"):
                    cons.append(str(cond(e.cond)))
                elif e.kind in ("else", "exit"):
                    base = e.cond[0] if isinstance(e.cond, tuple) else e.cond
                    cons.append(str(Not(cond(base))))
        stmt_blocks = [b for b in p if cfg.blocks[b].stmts]
        uncovered = [b for b in stmt_blocks
                     if not any(getattr(st, "line", None) in cov_lines
                                or getattr(st, "pos", None) in cov_lines
                                for st in cfg.blocks[b].stmts)]
        if uncovered and stmt_blocks:
            gaps.append({"path": p, "constraints": sorted(set(cons)),
                         "uncovered_blocks": uncovered})
    return gaps
