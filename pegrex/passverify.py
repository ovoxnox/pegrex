"""passverify.py -- compiler-pass verification: an IR transformation is
correct iff the before/after CFGs are bisimilar."""

from __future__ import annotations

from .bisim import bisimilar


def verify_pass(cfg_before, cfg_after, cond, render, unroll=2) -> bool:
    """A local, semantics-preserving optimization is bisimulation-invariant."""
    return bisimilar(cfg_before, cfg_after, cond, cond, render, render, unroll)
