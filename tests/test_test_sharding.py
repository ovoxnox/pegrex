from __future__ import annotations

import pytest

from tools.run_test_shard import ROOT, TEST_ROOT, estimate, plan


def test_test_shard_plan_is_deterministic_and_complete():
    first = plan(4)
    second = plan(4)
    assert first == second
    flattened = [path for shard in first for path in shard]
    expected = sorted(path.relative_to(ROOT).as_posix() for path in TEST_ROOT.rglob("test_*.py"))
    assert len(flattened) == len(set(flattened))
    assert sorted(flattened) == expected
    assert all(shard for shard in first)


def test_test_shard_plan_balances_estimated_test_counts():
    weights = [sum(estimate(ROOT / path) for path in shard) for shard in plan(4)]
    assert max(weights) - min(weights) <= 10


def test_test_shard_rejects_zero_shards():
    with pytest.raises(ValueError):
        plan(0)
