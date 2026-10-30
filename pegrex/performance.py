"""Bounded profiling, deterministic audit modes, and reusable solver helpers."""
from __future__ import annotations
from collections import OrderedDict
from dataclasses import dataclass, field
from time import perf_counter
from typing import Callable, Any

@dataclass
class AnalysisProfile:
    started: float = field(default_factory=perf_counter)
    counters: dict[str, int] = field(default_factory=dict)
    timings: dict[str, float] = field(default_factory=dict)
    def count(self, name: str, amount: int = 1): self.counters[name] = self.counters.get(name, 0) + amount
    def measure(self, name: str, fn: Callable, *args, **kwargs):
        start = perf_counter()
        try: return fn(*args, **kwargs)
        finally: self.timings[name] = self.timings.get(name, 0.0) + (perf_counter() - start)
    def snapshot(self):
        return {"elapsed_seconds": round(perf_counter() - self.started, 6), "counters": dict(sorted(self.counters.items())), "timings_seconds": {k: round(v, 6) for k, v in sorted(self.timings.items())}}

@dataclass(frozen=True)
class AuditMode:
    name: str
    max_paths: int
    max_solver_calls: int
    max_seconds: float
    max_memory_mb: int
    adaptive: bool

MODES = {"fast": AuditMode("fast", 250, 100, 3.0, 512, False), "deep": AuditMode("deep", 10000, 5000, 120.0, 4096, True)}
def audit_mode(name: str) -> AuditMode:
    try: return MODES[name]
    except KeyError as exc: raise ValueError("mode must be 'fast' or 'deep'") from exc

class BoundedMemo:
    def __init__(self, maxsize: int = 2048):
        if maxsize < 1: raise ValueError("maxsize must be positive")
        self.maxsize = maxsize; self._items = OrderedDict(); self.hits = 0; self.misses = 0
    def get_or_compute(self, key: Any, compute: Callable[[], Any]):
        if key in self._items:
            self.hits += 1; self._items.move_to_end(key); return self._items[key]
        self.misses += 1; value = compute(); self._items[key] = value; self._items.move_to_end(key)
        while len(self._items) > self.maxsize: self._items.popitem(last=False)
        return value
    def stats(self): return {"size": len(self._items), "maxsize": self.maxsize, "hits": self.hits, "misses": self.misses}

def simplify_conjunction(terms):
    """Cheap, sound syntactic simplification; no solver-based claims."""
    out, seen = [], set()
    for term in terms:
        text = str(term).strip()
        if not text or text == "True": continue
        if text == "False": return ["False"]
        if text not in seen: seen.add(text); out.append(text)
    return out

class IRInterner:
    """Structural hash-consing for JSON-like immutable IR records."""
    def __init__(self): self._items = {}
    def intern(self, value):
        import hashlib, json
        canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
        key = hashlib.sha256(canonical.encode()).hexdigest()
        if key not in self._items:
            # Round-trip to detach caller-owned mutable containers.
            self._items[key] = json.loads(canonical)
        return self._items[key]
    def __len__(self): return len(self._items)


def rank_path_frontier(paths):
    """Deterministic heuristic priority: risk and uncertainty first, cheap proofs next."""
    def score(row):
        risk = max(0.0, float(row.get("risk", 0.0)))
        uncertainty = max(0.0, float(row.get("uncertainty", 0.0)))
        cost = max(0.001, float(row.get("proof_cost", 1.0)))
        return (-(risk * (1.0 + uncertainty) / cost), str(row.get("id", "")))
    return sorted(paths, key=score)


def memory_aware_batches(items, estimate_bytes, *, max_memory_mb=512):
    """Yield deterministic batches that fit a conservative estimated memory budget."""
    budget = max(1, int(max_memory_mb)) * 1024 * 1024
    batch, used = [], 0
    for item in items:
        size = max(1, int(estimate_bytes(item)))
        if batch and used + size > budget:
            yield batch; batch, used = [], 0
        if size > budget:
            # Oversize tasks are yielded alone; callers can return UNKNOWN or
            # refuse them instead of accidentally exceeding the aggregate cap.
            yield [item]
            continue
        batch.append(item); used += size
    if batch: yield batch


def select_solver_portfolio(obligation: dict) -> tuple[str, ...]:
    """Choose a deterministic solver order from obligation shape, not runtime guesswork."""
    shape = str(obligation.get("shape", "general")).lower()
    if shape in {"linear-integer", "difference-logic", "bounds"}: return ("specialized-linear", "smt")
    if shape in {"bitvector", "overflow", "machine-integer"}: return ("bitvector-smt", "smt")
    if shape in {"finite-domain", "enumerated"}: return ("finite-domain", "smt")
    if shape in {"string", "regex"}: return ("regex-bounded", "smt")
    return ("smt",)


def merge_parallel_results(results):
    """Deterministically merge result shards while preserving unknowns and provenance."""
    findings, unknowns, coverage = {}, {}, []
    for shard in results:
        for finding in shard.get("findings", []):
            import json
            key = json.dumps(finding, sort_keys=True, separators=(",", ":"), default=str)
            findings[key] = finding
        for unknown in shard.get("unknowns", []):
            import json
            key = json.dumps(unknown, sort_keys=True, separators=(",", ":"), default=str)
            unknowns[key] = unknown
        if shard.get("coverage") is not None: coverage.append(shard["coverage"])
    return {"findings": [findings[k] for k in sorted(findings)],
            "unknowns": [unknowns[k] for k in sorted(unknowns)],
            "coverage": coverage, "shards": len(results), "deterministic_merge": True}

# Per-analysis solver accounting. Calls outside an explicit analysis scope are
# still allowed, but are not attributed to a session or charged to its budget.
from contextlib import contextmanager
from contextvars import ContextVar


class SolverBudgetExceeded(RuntimeError):
    """Raised before a solver call that would exceed the active analysis budget."""


_ACTIVE_PROFILE: ContextVar[AnalysisProfile | None] = ContextVar("pegrex_analysis_profile", default=None)
_ACTIVE_SOLVER_BUDGET: ContextVar[dict | None] = ContextVar("pegrex_solver_budget", default=None)


@contextmanager
def analysis_scope(profile: AnalysisProfile, *, max_solver_calls: int | None = None):
    """Attribute profiling and solver calls to one analysis operation."""
    budget = {"max": max_solver_calls, "calls": 0}
    profile_token = _ACTIVE_PROFILE.set(profile)
    budget_token = _ACTIVE_SOLVER_BUDGET.set(budget)
    try:
        yield budget
    finally:
        _ACTIVE_SOLVER_BUDGET.reset(budget_token)
        _ACTIVE_PROFILE.reset(profile_token)


def record_solver_call(backend: str = "unknown") -> None:
    """Charge a solver invocation before entering the backend's expensive call."""
    budget = _ACTIVE_SOLVER_BUDGET.get()
    profile = _ACTIVE_PROFILE.get()
    if budget is not None:
        limit = budget["max"]
        if limit is not None and budget["calls"] >= limit:
            if profile is not None:
                profile.count("solver_budget_refusals")
            raise SolverBudgetExceeded(f"solver-call budget exceeded ({limit})")
        budget["calls"] += 1
    if profile is not None:
        profile.count("solver_calls")
        profile.count(f"solver_calls.{backend}")
