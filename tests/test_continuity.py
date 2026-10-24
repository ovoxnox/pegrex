import pathlib
import tempfile

from pegrex.continuity import (compare_snapshots, continuity_certificate,
                               render_report)


def _snap(files):
    d = tempfile.mkdtemp()
    for name, src in files.items():
        (pathlib.Path(d) / name).write_text(src)
    return d


def test_unchanged_function_is_identical():
    src = "def f(n):\n    return n\n"
    old, new = _snap({"m.py": src}), _snap({"m.py": src})
    r = compare_snapshots(old, new)
    assert "m.py::f" in r["identical"]


def test_textually_different_but_equivalent_is_identical():
    old = _snap({"m.py": "def f(n):\n    return n + n\n"})
    new = _snap({"m.py": "def f(n):\n    return n * 2\n"})
    r = compare_snapshots(old, new)
    assert "m.py::f" in r["identical"]


def test_class_methods_are_compared_dedented():
    old = _snap({"m.py": "class C:\n    def f(self, n):\n        return n\n"})
    new = _snap({"m.py": "class C:\n    def f(self, n):\n        return n\n"})
    r = compare_snapshots(old, new)
    assert "m.py::C.f" in r["identical"]


def test_added_and_removed_functions_and_modules_are_named():
    old = _snap({"a.py": "def f(n):\n    return n\n",
                "gone.py": "def g(n):\n    return n\n"})
    new = _snap({"a.py": "def f(n):\n    return n\n\ndef h(n):\n    return n\n",
                "new.py": "def k(n):\n    return n\n"})
    r = compare_snapshots(old, new)
    assert "a.py::h" in r["added_functions"]
    assert "gone.py" in r["removed_modules"]
    assert "new.py" in r["added_modules"]


def test_real_behavior_change_is_caught_with_counterexample():
    old = _snap({"m.py": "def f(n):\n    if n > 0:\n        return 1\n"
                         "    return -1\n"})
    new = _snap({"m.py": "def f(n):\n    if n > 0:\n        return -1\n"
                         "    return 1\n"})
    cert = continuity_certificate(old, new)
    assert cert["status"] == "evolved"
    assert cert["changed"][0]["function"] == "m.py::f"
    assert cert["changed"][0]["counterexample"] is not None


def test_nonarithmetic_function_is_incomplete_not_skipped():
    old = _snap({"m.py": "def f(xs):\n    return [x for x in xs if x]\n"})
    new = _snap({"m.py": "def f(xs):\n    return [x for x in xs if not x]\n"})
    cert = continuity_certificate(old, new)
    assert cert["status"] == "incomplete"
    assert len(cert["unknown"]) == 1


def test_status_continuous_when_everything_identical():
    src = {"m.py": "def f(n):\n    return n\n"}
    cert = continuity_certificate(_snap(src), _snap(src))
    assert cert["status"] == "continuous"


def test_render_report_includes_labels():
    src = {"m.py": "def f(n):\n    return n\n"}
    cert = continuity_certificate(_snap(src), _snap(src), "A", "B")
    rendered = render_report(cert)
    assert "A -> B" in rendered and "continuous" in rendered
