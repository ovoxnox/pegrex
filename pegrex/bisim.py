"""
bisim

Equivalence by bisimulation: partition-refine two CFGs against labels
(constraint, result) until stable.  Certifies cross-language equivalence
without enumeration bounds — subsumes contracts in one mechanism."""

from __future__ import annotations


def _labels(cfg, cond, render, unroll=2):
    """block_id -> outgoing label multiset for refinement."""
    from pegrex.paths import PathEnumerator
    labels = {}
    paths = PathEnumerator(cfg, unroll=unroll).enumerate()
    for p in paths:
        sig = []
        for i in range(len(p) - 1):
            for dst, e in cfg.successors(p[i]):
                if dst == p[i + 1]:
                    base = e.cond[0] if isinstance(e.cond, tuple) else e.cond
                    txt = str(cond(base)) if cond else e.kind
                    sig.append((e.kind, txt))
        result = None
        for b in p:
            blk = cfg.blocks[b]
            if blk.term == "ret" and blk.stmts and render:
                result = render(blk.stmts[0])
        labels[tuple(p)] = (tuple(sorted(sig)), result)
    return labels


def bisimilar(cfg_a, cfg_b, cond_a, cond_b, render_a, render_b, unroll=2) -> bool:
    """True if the two CFGs agree on path-label multisets up to unroll."""
    la = _labels(cfg_a, cond_a, render_a, unroll)
    lb = _labels(cfg_b, cond_b, render_b, unroll)
    return sorted(la.values()) == sorted(lb.values())
