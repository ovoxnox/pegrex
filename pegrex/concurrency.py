"""Optional, deterministic, cross-platform process parallelism.

Sequential execution is the default and remains preferred for small inputs.
Process pools use ``spawn`` explicitly for Linux/Windows/macOS parity.  Only
top-level picklable functions and picklable task values are accepted.
"""
from __future__ import annotations

import multiprocessing as mp
import time
from concurrent.futures import ProcessPoolExecutor


def process_map(function, items, *, workers: int = 1, min_parallel: int = 32):
    """Map in input order; use processes only by explicit opt-in/policy."""
    tasks = list(items)
    if workers <= 1 or len(tasks) < max(1, min_parallel):
        return [function(task) for task in tasks]
    context = mp.get_context("spawn")
    with ProcessPoolExecutor(max_workers=workers, mp_context=context) as pool:
        return list(pool.map(function, tasks))


def benchmark_process_map(function, items, *, workers: int = 2) -> dict:
    """Measure process startup overhead even on repositories below the policy threshold."""
    tasks = list(items)
    started = time.perf_counter()
    sequential = [function(task) for task in tasks]
    sequential_seconds = time.perf_counter() - started
    started = time.perf_counter()
    parallel = process_map(function, tasks, workers=workers, min_parallel=1)
    parallel_seconds = time.perf_counter() - started
    if parallel != sequential:
        raise RuntimeError("parallel and sequential results differ")
    return {
        "items": len(tasks), "workers": workers, "context": "spawn",
        "sequential_seconds": sequential_seconds,
        "parallel_seconds": parallel_seconds,
        "overhead_seconds": parallel_seconds - sequential_seconds,
        "speedup": (sequential_seconds / parallel_seconds
                    if parallel_seconds > 0 else None),
        "results_equal": True,
    }


def callgraph_worker(task):
    """Picklable directory-CLI worker: ``(path, language)`` -> ``(path, graph)``."""
    path, language = task
    from .callgraph import build_call_graph
    with open(path, encoding="utf-8") as handle:
        source = handle.read()
    return path, build_call_graph(source, language)
