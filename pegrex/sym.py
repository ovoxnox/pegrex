"""
║  The symbolic alphabet: immutable expression trees + the operator 
║  vocabulary shared by paths, contracts, guards, and loop forms."""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from threading import RLock
from typing import ClassVar
from weakref import WeakValueDictionary


@dataclass(frozen=True)
class Sym:
    name: str
    _nodes: ClassVar[WeakValueDictionary] = WeakValueDictionary()
    _lock: ClassVar[RLock] = RLock()

    def __new__(cls, name: str):
        key = (cls, name)
        with cls._lock:
            node = cls._nodes.get(key)
            if node is None:
                node = super().__new__(cls)
                cls._nodes[key] = node
            return node

    def __str__(self) -> str: return self.name


@dataclass(frozen=True)
class Op:
    op: str
    args: tuple
    _nodes: ClassVar[WeakValueDictionary] = WeakValueDictionary()
    _lock: ClassVar[RLock] = RLock()

    def __new__(cls, op: str, args: tuple):
        args = tuple(args)
        key = (cls, op, args)
        try:
            hash(key)
        except TypeError:
            return super().__new__(cls)
        with cls._lock:
            node = cls._nodes.get(key)
            if node is None:
                node = super().__new__(cls)
                cls._nodes[key] = node
            return node

    def __str__(self) -> str:
        if self.op == "not" and len(self.args) == 1:
            return f"(not {self.args[0]})"
        if self.op == "ite" and len(self.args) == 3:
            return f"(ite {self.args[0]} {self.args[1]} {self.args[2]})"
        return "(" + f" {self.op} ".join(str(a) for a in self.args) + ")"


def const(v):
    """Implement const with the module's explicit API and failure semantics."""
    if isinstance(v, bool):
        return "true" if v else "false"
    return v


def V(name: str) -> Sym:
    """Implement V with explicit API and failure semantics."""
    return Sym(name)
def And(*a):
    """Implement And with explicit API and failure semantics."""
    return Op('and', tuple(a))
def Or(*a):
    """Implement Or with explicit API and failure semantics."""
    return Op('or', tuple(a))
def Not(a):
    """Implement Not with explicit API and failure semantics."""
    return Op('not', (a,))
def Eq(a, b):
    """Implement Eq with explicit API and failure semantics."""
    return Op('=', (a, b))
def Lt(a, b):
    """Implement Lt with explicit API and failure semantics."""
    return Op('<', (a, b))
def Le(a, b):
    """Implement Le with explicit API and failure semantics."""
    return Op('<=', (a, b))
def Gt(a, b):
    """Implement Gt with explicit API and failure semantics."""
    return Op('>', (a, b))
def Ge(a, b):
    """Implement Ge with explicit API and failure semantics."""
    return Op('>=', (a, b))
def Add(a, b):
    """Implement Add with explicit API and failure semantics."""
    return Op('+', (a, b))
def Sub(a, b):
    """Implement Sub with explicit API and failure semantics."""
    return Op('-', (a, b))
def Mul(a, b):
    """Implement Mul with explicit API and failure semantics."""
    return Op('*', (a, b))
def Floordiv(a, b):
    """Implement Floordiv with explicit API and failure semantics."""
    return Op('//', (a, b))
def ite(c, t, e):
    """Implement ite with explicit API and failure semantics."""
    return Op('ite', (c, t, e))

OPS_TXT = {"<": Lt, "<=": Le, ">": Gt, ">=": Ge,
           "==": Eq, "!=": lambda a, b: Not(Eq(a, b))}


@lru_cache(maxsize=8192)
def _canonical_cached(expr):
    if isinstance(expr, Op):
        args = tuple(_canonical_cached(a) for a in expr.args)
        if expr.op in ("and", "or", "=", "==", "+", "*") \
                and len(args) == 2 and str(args[1]) < str(args[0]):
            args = (args[1], args[0])
        if expr.op == "not" and len(args) == 1 \
                and isinstance(args[0], Op) and args[0].op == "not":
            return args[0].args[0]
        return Op(expr.op, args)
    return expr


def canonical(expr):
    """Memoized structural normal form over immutable hash-consed nodes."""
    return _canonical_cached(expr)


canonical.cache_info = _canonical_cached.cache_info
canonical.cache_clear = _canonical_cached.cache_clear
