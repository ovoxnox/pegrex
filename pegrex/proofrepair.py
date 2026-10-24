"""
proofprepair -- patch the certificate, not the run 

║  When code changes, diff the AST; only re-verify paths whose blocks      
║  were touched.  The cache grows into incremental certification."""

from __future__ import annotations

import hashlib


def ast_fingerprint(node) -> str:
    """Stable structural hash of an AST subtree."""
    def rec(n):
        if hasattr(n, "tag"):
            return "(" + n.tag + " " + " ".join(rec(c)
                                                for c in n.children) + ")"
        if isinstance(n, list):
            return "[" + " ".join(rec(c) for c in n) + "]"
        return repr(n)[:20]
    return hashlib.sha256(rec(node).encode()).hexdigest()[:16]


def diff_blocks(old_tree, new_tree) -> set:
    """Fingerprints present in both but under different parents = changed
    regions; simplest sound approximation: fingerprints only in new."""
    def fps(t, acc):
        """fps(t, acc): see module docstring."""
        if hasattr(t, "tag"):
            acc.add(ast_fingerprint(t))
            for c in t.children:
                fps(c, acc)
        elif isinstance(t, list):
            for c in t:
                fps(c, acc)
        return acc
    return fps(new_tree, set()) - fps(old_tree, set())
