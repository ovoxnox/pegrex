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
    if isinstance(v, bool):
        return "true" if v else "false"
    return v


def V(name: str) -> Sym: return Sym(name)
def And(*a): return Op("and", tuple(a))
def Or(*a):  return Op("or", tuple(a))
def Not(a):  return Op("not", (a,))
def Eq(a, b): return Op("=", (a, b))
def Lt(a, b): return Op("<", (a, b))
def Le(a, b): return Op("<=", (a, b))
def Gt(a, b): return Op(">", (a, b))
def Ge(a, b): return Op(">=", (a, b))
def Add(a, b): return Op("+", (a, b))
def Sub(a, b): return Op("-", (a, b))
def Mul(a, b): return Op("*", (a, b))
def Floordiv(a, b): return Op("//", (a, b))
def ite(c, t, e): return Op("ite", (c, t, e))

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
