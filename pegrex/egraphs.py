"""
egraphs -- equality saturation for idiom rewriting 

║  Mini e-graph: union-find over expression nodes, rewrite rules applied 
║  until saturation, best extraction by cost. Upgrades the string-based 
║  compose into algebraic rewriting."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ENode:
    op: str
    args: tuple = ()
    value: object = None


class EGraph:
    def __init__(self) -> None:
        self.nodes: list = []
        self.parent: list = []

    def add(self, op: str, args=(), value=None) -> int:
        self.nodes.append(ENode(op, tuple(args), value))
        self.parent.append(len(self.parent))
        return len(self.parent) - 1

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[rb] = ra

    def saturated(self, rules) -> bool:
        """Apply rules until none fire. Returns True if fixed point."""
        changed = True
        while changed:
            changed = False
            for lhs_pat, rhs_pat in rules:
                for i, n in enumerate(self.nodes):
                    if self.find(i) != i:
                        continue
                    m = self._match(lhs_pat, n)
                    if m is not None:
                        r = self._build(rhs_pat, m)
                        if self.find(r) != self.find(i):
                            self.union(i, r)
                            changed = True
        return True

    def _match(self, pat, node):
        if isinstance(pat, int):
            return {pat: node.value} if node.op == "lit" else None
        op, *sub = pat
        if node.op != op:
            return None
        out = {}
        for p, a in zip(sub, node.args):
            m = self._match(p, self.nodes[a])
            if m is None:
                return None
            out.update(m)
        return out

    def _build(self, pat, m):
        if isinstance(pat, int):
            return self.add("lit", (), m[pat])
        op, *sub = pat
        return self.add(op, tuple(self._build(p, m) for p in sub))

    def extract(self, i: int, cost=lambda n: 1) -> object:
        """Cheapest representative expression."""
        root = self.find(i)
        best, bestc = None, float("inf")
        for j, n in enumerate(self.nodes):
            if self.find(j) == root:
                c = cost(n)
                if c < bestc:
                    best, bestc = n, c
        if best is None:
            return None
        if best.op == "lit":
            return best.value
        return (best.op, *[self.extract(a) for a in best.args])
