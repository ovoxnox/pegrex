#!/usr/bin/env python3
"""Run a deterministic, balanced shard of the PegRex pytest suite.

Test files are assigned with deterministic longest-processing-estimate-first
bin packing. Estimates count test functions and classes in the AST, so the
planner is dependency-free and never imports repository test code. This is a
scheduling heuristic, not a guarantee that wall-clock durations are equal.
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = ROOT / "tests"


def estimate(path: Path) -> int:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError):
        return 1
    count = 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            count += 1
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            count += 2
    return max(count, 1)


def plan(shards: int) -> list[list[str]]:
    if shards < 1:
        raise ValueError("shards must be >= 1")
    paths = sorted(TEST_ROOT.rglob("test_*.py"))
    bins: list[list[str]] = [[] for _ in range(shards)]
    loads = [0] * shards
    weighted = [(estimate(path), path.relative_to(ROOT).as_posix()) for path in paths]
    # Stable tie-breaks make the same source tree produce the same plan.
    for weight, name in sorted(weighted, key=lambda row: (-row[0], row[1])):
        target = min(range(shards), key=lambda index: (loads[index], index))
        bins[target].append(name)
        loads[target] += weight
    return [sorted(items) for items in bins]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shard", type=int, help="zero-based shard index")
    parser.add_argument("--shards", type=int, default=4)
    parser.add_argument("--list", action="store_true", help="print the deterministic plan as JSON")
    args = parser.parse_args()
    if args.shards < 1:
        parser.error("--shards must be >= 1")
    bins = plan(args.shards)
    if args.list:
        print(json.dumps({"format": "pegrex.test-shard-plan.v1", "shards": bins,
                          "weights": [sum(estimate(ROOT / name) for name in items) for items in bins]}, indent=2))
        return 0
    if args.shard is None or not 0 <= args.shard < args.shards:
        parser.error("provide --shard in [0, --shards)")
    selected = bins[args.shard]
    if not selected:
        print(f"shard {args.shard} has no test files", file=sys.stderr)
        return 2
    print(f"PegRex test shard {args.shard + 1}/{args.shards}: {len(selected)} files")
    os.chdir(ROOT)
    os.execv(sys.executable, [sys.executable, "-m", "pytest", "-q", "--tb=short", *selected])
    return 127  # pragma: no cover - exec replaces this process


if __name__ == "__main__":
    raise SystemExit(main())
