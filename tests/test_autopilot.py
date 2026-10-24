import hashlib
import html
import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

try:
    import pytest
except ImportError:
    class _Raises:
        def __init__(self, exc): self.exc = exc
        def __enter__(self): return self
        def __exit__(self, t, v, tb):
            assert t is not None and issubclass(t, self.exc), f"expected {self.exc}"
            return True
    class _PytestShim:
        @staticmethod
        def raises(exc): return _Raises(exc)
    pytest = _PytestShim()

from pegrex.attest import canonical_json, hmac_verify
from pegrex.autopilot import (AutopilotError, build_report, verify_report)

KEY = "test-autopilot-key"


@pytest.fixture()
def fixture_tree(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "tainted.py").write_text(
        "# pii: email\n"
        "# sink: send_grid needs consent\n"
        "def signup():\n"
        "    user_input = email\n"
        "    send_grid(user_input)\n"
        "    return 1\n")
    (src / "complex.py").write_text(
        "def messy(n):\n"
        "    if n > 0:\n"
        "        if n > 10:\n"
        "            if n > 100:\n"
        "                if n > 1000:\n"
        "                    if n > 10000:\n"
        "                        if n > 100000:\n"
        "                            return 6\n"
        "                        return 5\n"
        "                    return 4\n"
        "                return 3\n"
        "            return 2\n"
        "        return 1\n"
        "    return 0\n")
    (src / "proven.py").write_text(
        "def clamp_nonneg(n):\n"
        "    if n < 0:\n        return 0\n    return n\n")
    (src / "LEGAL.md").write_text(
        "Acme shall deliver reports within 30 days.\n")
    return src


def test_report_contains_all_categories(fixture_tree, tmp_path):
    out = build_report(fixture_tree, tmp_path / "r.html", KEY)
    assert out["ok"] is True and out["files"] == 3
    text = (tmp_path / "r.html").read_text()
    for needle in ("gdpr-no-consent", "cognitive-over-budget",
                   "contracts-extracted", "Acme"):
        assert needle in text


def test_signature_verifies_with_key_not_without(fixture_tree, tmp_path):
    out = build_report(fixture_tree, tmp_path / "r.html", KEY)
    text = (tmp_path / "r.html").read_text()
    assert verify_report(text, KEY)["ok"] is True
    assert not verify_report(text, "nope")["ok"]


def test_manifest_sha256_matches_actual(fixture_tree, tmp_path):
    out = build_report(fixture_tree, tmp_path / "r.html", KEY)
    text = (tmp_path / "r.html").read_text()
    start = text.find("id='pegrex-manifest'>")
    start = text.find(">", start) + 1
    env = json.loads(text[start:text.find("</script>", start)])
    actual = hashlib.sha256(
        canonical_json(env["manifest"]).encode()).hexdigest()
    assert actual == env["manifest_sha256"] == out["manifest_sha256"]


def test_tampered_report_refused(fixture_tree, tmp_path):
    build_report(fixture_tree, tmp_path / "r.html", KEY)
    text = (tmp_path / "r.html").read_text()
    assert not verify_report(text.replace("messy", "tidy"), KEY)["ok"]


def test_details_manifest_round_trip(fixture_tree, tmp_path):
    build_report(fixture_tree, tmp_path / "r.html", KEY)
    text = (tmp_path / "r.html").read_text()
    pre = text.split("<pre>", 1)[1].split("</pre>", 1)[0]
    env = json.loads(html.unescape(pre))
    assert hmac_verify(env["manifest"], KEY, env["signature"])
    assert hashlib.sha256(
        canonical_json(env["manifest"]).encode()).hexdigest() \
        == env["manifest_sha256"]


def test_deadlines_included(fixture_tree, tmp_path):
    out = build_report(fixture_tree, tmp_path / "r.html", KEY)
    assert out["deadlines"]
    assert any(d.get("party") == "Acme" for d in out["deadlines"])


def test_empty_tree_refused(tmp_path):
    with pytest.raises(AutopilotError) as ei:
        build_report(tmp_path, tmp_path / "r.html", KEY)
    assert "nothing to audit" in str(ei.value if hasattr(ei, "value") else ei)


def test_pycache_skipped(fixture_tree, tmp_path):
    cache = fixture_tree / "__pycache__"
    cache.mkdir()
    (cache / "junk.py").write_text("def j():\n    return 1\n")
    pegrex_cache = fixture_tree / ".pegrex-cache"
    pegrex_cache.mkdir()
    (pegrex_cache / "junk2.py").write_text("def k():\n    return 2\n")
    out = build_report(fixture_tree, tmp_path / "r.html", KEY)
    assert out["files"] == 3


def test_refusals_recorded_not_fatal(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "weird.py").write_text(
        "import os\n"                      # audit_gdpr unsupported stmt
        "def f(n):\n"
        "    return n\n")
    out = build_report(src, tmp_path / "r.html", KEY)
    assert out["ok"] is True
    text = (tmp_path / "r.html").read_text()
    assert "audit-refused" in text or "contracts-extracted" in text
