import os
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

import pytest

from pegrex.llmcegis import (HTTProposer, LLMProposerError, TemplateProposer,
                             repair)
from pegrex.semantics import verify_patch

BEFORE = "def f(n):\n    if n > 0:\n        return n + 2\n    return n\n"
REF = "def classify(n):\n    if n > 0:\n        return 1\n    return -1\n"
WRONG = "def classify(n):\n    return 1\n"
FIXED = "def classify(n):\n    if n <= 0:\n        return -1\n    return 1\n"


def test_template_repair_constant_adjustment():
    tp = TemplateProposer(BEFORE)
    out = repair(BEFORE, proposer=tp, max_rounds=6)
    assert out["repaired"] is True
    assert out["rounds"] <= 6
    assert out["final"]["verified"] is True
    assert any(h["status"] == "refused" for h in out["history"])
    # independent proof of the found patch
    tmp = tempfile.mkdtemp()
    bp, pp = os.path.join(tmp, "b.py"), os.path.join(tmp, "p.py")
    open(bp, "w").write(BEFORE)
    open(pp, "w").write(tp.last_candidate)
    assert verify_patch(bp, pp)["verified"] is True


def test_proposer_kind_strings():
    out = repair(BEFORE, proposer="templates", max_rounds=6)
    assert out["repaired"] is True and out["proposer"] == "templates"
    with pytest.raises(LLMProposerError):
        repair(BEFORE, proposer="bogus-kind", max_rounds=1)


def test_callable_proposer_receives_counterexample():
    calls = []

    def proposer(feedback):
        calls.append(feedback)
        return WRONG if feedback is None else FIXED

    out = repair(REF, proposer=proposer, max_rounds=4)
    assert out["repaired"] is True
    assert out["proposer"] == "proposer"
    assert calls[0] is None
    assert calls[1]["counterexample"] is not None
    assert calls[1]["failing_paths"]


def test_http_proposer_refuses_without_endpoint(monkeypatch=None):
    os.environ.pop("PEGREX_LLM_ENDPOINT", None)
    with pytest.raises(LLMProposerError) as exc:
        HTTProposer()({"counterexample": None})
    assert "PEGREX_LLM_ENDPOINT not set" in str(exc.value)
    out = repair(REF, proposer=HTTProposer(), max_rounds=2)
    assert out["repaired"] is False
    assert all(h["status"] == "proposer-error" for h in out["history"])


def test_unrepairable_claim_exhausts_honestly():
    out = repair(REF, proposer=lambda fb: WRONG, max_rounds=3)
    assert out["repaired"] is False
    assert out["rounds"] == 3
    assert out["final"]["verified"] is False
    assert out["final"]["counterexample"]              # a real refusal, not a shrug
    assert all(h["status"] == "refused" for h in out["history"])


def test_garbage_proposal_marked_invalid_and_loop_continues():
    seq = iter(["def classify(n):\n    return [\n", FIXED])
    out = repair(REF, proposer=lambda fb: next(seq), max_rounds=4)
    assert out["history"][0]["status"] == "invalid"
    assert out["repaired"] is True                     # recovered next round


def test_template_proposer_never_emits_invalid_python():
    tp = TemplateProposer(BEFORE)
    for fb in (None,
               {"counterexample": {"inputs": {"n": 1}, "path": ["(n > 0)"]},
                "failing_paths": []}):
        cand = tp(fb)
        if cand is not None:
            compile(cand, "<cand>", "exec")            # parse-checked already
