import os
import tempfile

from pegrex.prchat import answer_question, propose_from_question, render_pr_comment


def _write(src):
    fd, p = tempfile.mkstemp(suffix=".py")
    with os.fdopen(fd, "w") as f:
        f.write(src)
    return p


def test_question_template_matches_reject_negative_phrasing():
    assert propose_from_question("does this reject negative balances?") == \
        ["balances >= 0"]


def test_question_template_matches_is_x_non_negative():
    assert propose_from_question("is n always non-negative?") == ["n >= 0"]


def test_falls_through_to_declarative_nlspec_templates():
    cands = propose_from_question("n is positive")
    assert "n > 0" in cands


def test_unrecognized_phrasing_yields_no_candidates():
    assert propose_from_question("what time is it?") == []


def test_proven_case():
    p = _write("def clamp_nonneg(n):\n    if n < 0:\n        return 0\n    return n\n")
    out = answer_question(p, "is the result always non-negative?")
    assert out["status"] == "answered"
    assert out["candidates"][0]["status"] == "proven"


def test_refuted_case_has_counterexample():
    p = _write("def f(n):\n    if n > 10:\n        return -1\n    return n\n")
    out = answer_question(p, "is the result always non-negative?")
    cand = out["candidates"][0]
    assert cand["status"] == "dropped"
    assert cand["counterexample"]["inputs"]["n"] > 10
    assert cand["counterexample"]["path_result"] == "-1"


def test_unknown_case_stays_unknown():
    p = _write("def sub(a, b):\n    return a - b\n")
    out = answer_question(p, "is the result always non-negative?")
    assert out["candidates"][0]["status"] == "unknown"


def test_no_template_question_is_refused():
    p = _write("def g(n):\n    return n\n")
    out = answer_question(p, "what color is the sky?")
    assert out["status"] == "no-template"
    assert out["candidates"] == []


def test_render_pr_comment_no_template():
    rendered = render_pr_comment({"status": "no-template",
                                  "question": "huh?", "candidates": []})
    assert "won't guess" in rendered
    assert "huh?" in rendered


def test_render_pr_comment_proven():
    rendered = render_pr_comment({
        "status": "answered", "question": "q",
        "candidates": [{"candidate": "x >= 0", "status": "proven"}]})
    assert "\u2705" in rendered and "x >= 0" in rendered
