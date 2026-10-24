"""
memory — symbolic memory model (KLEE-lite slice)  

║  Memory objects with symbolic offsets; every access gets a verdict:     
║    safe         -- constraints PROVE 0 <= idx < size (FM entailment)    
║    provably-oob -- constraints PROVE idx < 0 or idx >= size  
║    maybe-oob    -- neither discharges: reported, never guessed 

║  Aliasing: must-alias / no-alias / may-alias, same discipline.  
║  This is the seam field-sensitive taint and veritesting build on. """

from __future__ import annotations

from dataclasses import dataclass

from .ir import lower_condition
from .linsolve import LinearBackend, atoms_of

DEFAULT_LB = LinearBackend()


@dataclass(frozen=True)
class MemObject:
    """MemObject - see module docstring."""
    name: str
    size: int  # elements


@dataclass(frozen=True)
class Pointer:
    obj: MemObject
    offset: str  # linear expression text, e.g. "i + 1"


class Memory:
    """A small store of objects + access/alias judgments."""

    def __init__(self, lb=None):
        """  init  (lb): see module docstring."""
        self.lb = lb or DEFAULT_LB
        self.objects = {}

    def alloc(self, name, size) -> MemObject:
        """alloc(name, size): see module docstring."""
        obj = MemObject(name, size)
        self.objects[name] = obj
        return obj

    def access(self, obj, idx_text, constraint_texts, lb=None) -> dict:
        """Bounds verdict for obj[idx] under the path constraints."""
        lb = lb or self.lb
        atoms = []
        for c in constraint_texts:
            try:
                atoms += atoms_of(lower_condition(c))
            except Exception:
                pass  # opaque: dropped, safe direction
        model = lb.learn(atoms)
        lo_ok = lb.entails(model, lower_condition(f"{idx_text} >= 0"))
        hi_ok = lb.entails(model,
                           lower_condition(f"{idx_text} <= {obj.size - 1}"))
        if lo_ok and hi_ok:
            return {"status": "safe", "object": obj.name}
        lo_bad = lb.entails(model, lower_condition(f"{idx_text} < 0"))
        hi_bad = lb.entails(model,
                            lower_condition(f"{idx_text} >= {obj.size}"))
        if lo_bad or hi_bad:
            return {"status": "provably-oob", "object": obj.name,
                    "low": bool(lo_bad), "high": bool(hi_bad)}
        return {"status": "maybe-oob", "object": obj.name,
                "low_proven": bool(lo_ok), "high_proven": bool(hi_ok)}

    def alias(self, p1: Pointer, p2: Pointer,
              constraint_texts=(), lb=None) -> dict:
        """Aliasing judgment for two pointers.

        must-alias : same object AND constraints prove equal offsets
        no-alias   : different objects, OR proven disjoint ranges
        may-alias  : otherwise -- reported, never guessed"""
        lb = lb or self.lb
        if p1.obj.name != p2.obj.name:
            return {"status": "no-alias", "reason": "different-objects"}
        atoms = []
        for c in constraint_texts:
            try:
                atoms += atoms_of(lower_condition(c))
            except Exception:
                pass
        model = lb.learn(atoms)
        try:
            if lb.entails(model, lower_condition(
                    f"({p1.offset}) - ({p2.offset}) = 0")):
                return {"status": "must-alias", "object": p1.obj.name}
            if lb.entails(model, lower_condition(
                    f"({p1.offset}) - ({p2.offset}) >= 1")) or \
               lb.entails(model, lower_condition(
                    f"({p2.offset}) - ({p1.offset}) >= 1")):
                return {"status": "no-alias", "reason": "proven-distinct-offsets"}
        except Exception:
            pass
        return {"status": "may-alias", "object": p1.obj.name}
