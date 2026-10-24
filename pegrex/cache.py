"""
cache

Content-addressed analysis cache: re-running on an unchanged file is
O(1).  Keyed by sha256(source) + analyzer set — the TDD loop's speed."""

from __future__ import annotations

import hashlib
import json
import pathlib

from .contract import StructuralError


class AnalysisCache:
    """AnalysisCache - see module docstring."""
    def __init__(self, root: str | pathlib.Path = ".pegrex-cache") -> None:
        self.root = pathlib.Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def key(self, source: str, analyzers: tuple[str, ...]) -> pathlib.Path:
        h = hashlib.sha256(source.encode()).hexdigest()[:16]
        a = hashlib.sha256(",".join(sorted(analyzers)).encode()).hexdigest()[:8]
        return self.root / f"{h}-{a}.json"

    def get(self, source: str, analyzers: tuple[str, ...]):
        p = self.key(source, analyzers)
        if p.exists():
            return json.loads(p.read_text())
        return None

    def put(self, source: str, analyzers: tuple[str, ...], payload: dict) -> None:
        self.key(source, analyzers).write_text(json.dumps(payload))


def memoized_compose(compose_fn):
    """compose(caller_contract, callee, callee_contract, param, arg) with a
    per-call-site contract cache: whole-program analysis becomes near-linear
    on shared callees."""
    cache: dict = {}

    def wrapper(caller, callee_name, callee_contract, param, arg):
        """wrapper(caller, callee_name, callee_contract, param, arg)"""
        key = (callee_name, param, arg,
               hash(repr(callee_contract)) & 0xFFFFFFFF)
        if key not in cache:
            cache[key] = compose_fn([(frozenset(), f"{callee_name}({arg})")],
                                    callee_name, callee_contract, param, arg)
        return cache[key]

    return wrapper
