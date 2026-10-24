"""
octagon — octagon abstract domain (core slice) 

║  Constraints ±x ± y <= c over 2n virtual vars {v+, v-}; closure is      
║  all-pairs shortest paths (Floyd-Warshall). strictly more precise than  
║  intervals: from {x+y<=4, x-y<=2} derives x<=3, which no interval      
║  bound can see. Empty domain = negative cycle. Widening = edge-wise     
║  max (standard), certified against the m77 FM solver differentially."""

from __future__ import annotations

import re
from fractions import Fraction

_INF = float("inf")
_ATOM = re.compile(r"^\(?\s*(?P<a>-?)\s*(?P<x>[A-Za-z_]\w*)\s*"
                   r"(?P<sg>[+-])\s*(?P<b>-?)\s*(?P<y>[A-Za-z_]\w*)"
                   r"\s*<=\s*(?P<c>-?\d+)\s*\)?$")
_UNARY = re.compile(r"^\(?\s*(?P<a>-?)\s*(?P<x>[A-Za-z_]\w*)"
                    r"\s*<=\s*(?P<c>-?\d+)\s*\)?$")


def parse_oct_atom(txt):
    """'x + y <= 4' -> (x, 1, y, 1, 4); unary 'x <= 3' -> (x, 1, None, None, 3).
    Raises ValueError outside the octagon fragment."""
    t = txt.strip()
    while t.startswith("(") and t.endswith(")"):
        t = t[1:-1].strip()
    m = _ATOM.match(t)
    if m:
        if m.group("x") == m.group("y"):
            raise ValueError(f"octagon: same-var atom {txt!r}")
        ax = -1 if m.group("a") == "-" else 1
        by = -1 if m.group("b") == "-" else 1
        if m.group("sg") == "-":
            by = -by
        return m.group("x"), ax, m.group("y"), by, int(m.group("c"))
    u = _UNARY.match(t)
    if u:
        ax = -1 if u.group("a") == "-" else 1
        return u.group("x"), ax, None, None, int(u.group("c"))
    raise ValueError(f"octagon: not an octagon atom {txt!r}")


class Octagon:
    """Closed octagon over named vars."""

    def __init__(self, atoms=()):
        self.edges = {}        # (u, v) -> weight; u,v are 'v+'/'v-'
        self._closed = False   # memoized: see close()
        for a in atoms:
            self.add(a)

    def add(self, txt):
        x, ax, y, by, c = parse_oct_atom(txt)
        def node(v, s): return f"{v}{'+' if s > 0 else '-'}"
        self._closed = False   # edges changed: cache is stale
        if y is None:
            # ax*x <= c  ==  ax*x - (-ax)*x <= 2c : exactly ONE DBM edge
            self.edges[(node(x, -ax), node(x, ax))] = min(
                self.edges.get((node(x, -ax), node(x, ax)), _INF), 2 * c)
            return self
        # ax*x + by*y <= c  ==  ax*x - (-by)*y <= c : edge (-by)y -> (ax)x, w=c
        e1 = (node(y, -by), node(x, ax))
        e2 = (node(x, -ax), node(y, by))      # swapped reading
        for e in (e1, e2):
            if e[0] == e[1]:
                raise ValueError(f"octagon: self-loop {txt!r}")
            self.edges[e] = min(self.edges.get(e, _INF), c)
        return self

    def _nodes(self):
        ns = set()
        for u, v in self.edges:
            ns.add(u); ns.add(v)
        return sorted(ns)

    def close(self):
        """In-place Floyd-Warshall closure, memoized against the current
        edge set. upper()/lower()/entails() each call close() -- checking
        bounds for several variables used to re-run the FULL O(n^3)
        closure once per variable even though nothing had changed since
        the previous call. add() is the only mutator and marks the cache
        stale; repeat calls with no intervening add() are now a no-op."""
        if self._closed:
            return self
        ns = self._nodes()
        d = {(u, v): (self.edges.get((u, v), _INF) if u != v else 0)
             for u in ns for v in ns}
        for k in ns:
            for u in ns:
                duk = d[(u, k)]
                if duk == _INF:
                    continue
                for v in ns:
                    alt = duk + d[(k, v)]
                    if alt < d[(u, v)]:
                        d[(u, v)] = alt
        self.edges = {(u, v): w for (u, v), w in d.items() if w < _INF and u != v}
        self._closed = True
        return self

    def feasible(self):
        """Negative-cycle check: Floyd-Warshall retaining the diagonal."""
        ns = self._nodes()
        d = {(u, v): (self.edges.get((u, v), _INF) if u != v else 0)
             for u in ns for v in ns}
        for k in ns:
            for u in ns:
                if d[(u, k)] == _INF:
                    continue
                for v in ns:
                    alt = d[(u, k)] + d[(k, v)]
                    if alt < d[(u, v)]:
                        d[(u, v)] = alt
        return all(d[(u, u)] >= 0 for u in ns)

    def upper(self, x):
        """x <= c : c = d(x-, x+)/2 (frac if odd)."""
        self.close()
        w = self.edges.get((f"{x}-", f"{x}+"), _INF)
        return None if w == _INF else Fraction(w, 2)

    def lower(self, x):
        w = self.edges.get((f"{x}+", f"{x}-"), _INF)
        return None if w == _INF else -Fraction(w, 2)

    def entails(self, atom_txt) -> bool:
        """Does the closed octagon entail the atom (binary or unary form)?"""
        x, ax, y, by, c = parse_oct_atom(atom_txt)
        self.close()
        def node(v, s): return f"{v}{'+' if s > 0 else '-'}"
        if y is None:
            w = self.edges.get((node(x, -ax), node(x, ax)), _INF)
            return w != _INF and Fraction(w, 2) <= c
        w = self.edges.get((node(y, -by), node(x, ax)), _INF)
        return w != _INF and w <= c


def widen(a: Octagon, b: Octagon) -> Octagon:
    """Standard widening: keep only bounds with identical value in both.
    Anything that moved (tightened or loosened) is dropped to top --
    unsound tightening is impossible, and the result over-approximates both."""
    out = Octagon()
    for e, w in a.edges.items():
        if b.edges.get(e) == w:
            out.edges[e] = w
    return out.close()
