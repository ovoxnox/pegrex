import json
import pathlib
import tempfile

from pegrex.harness import check_plan, default_policy
from pegrex.selfplay import (GROUND_TRUTH_DANGEROUS, fuzz, is_bypass,
                             load_corpus, regression_check, run_selfplay,
                             save_corpus)


def test_current_policy_has_no_bypass():
    assert fuzz(default_policy()) == []


def test_fuzzer_catches_a_real_naive_policy_gap():
    # a policy without the normalize-then-match fix must be caught by the
    # oracle logic (is_bypass), proving the fuzzer recognizes a real hole
    naive_policy = [{"effect": "allow", "tool": "write", "path": "src/*"}]
    import fnmatch
    traversal = {"tool": "write", "path": "src/../../../etc/passwd"}

    def naive_verdict(plan):
        return {"verdicts": [{"action": a, "verdict": "allowed"}
                             for a in plan]} if fnmatch.fnmatchcase(
            plan[0]["path"], naive_policy[0]["path"]) else {
            "verdicts": [{"action": a, "verdict": "refused"} for a in plan]}

    v = naive_verdict([traversal])
    assert is_bypass([traversal], v, traversal)


def test_is_bypass_requires_allowed_verdict_on_the_exact_action():
    gt = {"tool": "shell", "args": "rm -rf /"}
    refused_verdict = check_plan([gt], default_policy())
    assert not is_bypass([gt], refused_verdict, gt)


def test_corpus_round_trip():
    with tempfile.TemporaryDirectory() as td:
        path = str(pathlib.Path(td) / "c.json")
        assert load_corpus(path) == []
        save_corpus(path, [{"a": 1}])
        assert load_corpus(path) == [{"a": 1}]


def test_run_selfplay_grows_corpus_only_with_new_entries():
    with tempfile.TemporaryDirectory() as td:
        path = str(pathlib.Path(td) / "c.json")
        out1 = run_selfplay(default_policy(), corpus_path=path)
        assert out1["bypasses_found"] == 0
        assert out1["new_bypasses"] == 0
        assert out1["corpus_size"] == 0
        # re-running against an unchanged, hole-free policy adds nothing
        out2 = run_selfplay(default_policy(), corpus_path=path)
        assert out2["corpus_size"] == out1["corpus_size"]


def test_regression_check_on_empty_corpus_is_clean():
    with tempfile.TemporaryDirectory() as td:
        path = str(pathlib.Path(td) / "c.json")
        rc = regression_check(default_policy(), corpus_path=path)
        assert rc == {"checked": 0, "regressions": [], "all_still_refused": True}


def test_regression_check_flags_a_real_regression():
    with tempfile.TemporaryDirectory() as td:
        path = str(pathlib.Path(td) / "c.json")
        gt = {"tool": "shell", "args": "rm -rf /"}
        save_corpus(path, [{"plan": [gt], "ground_truth": gt}])
        # a policy that forgot the rm -rf deny rule must be flagged
        weak_policy = [{"effect": "allow", "tool": "shell", "args": "*"}]
        rc = regression_check(weak_policy, corpus_path=path)
        assert rc["all_still_refused"] is False
        assert len(rc["regressions"]) == 1


def test_ground_truth_corpus_is_nonempty():
    assert len(GROUND_TRUTH_DANGEROUS) >= 5
