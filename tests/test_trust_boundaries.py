import builtins

import pytest

from pegrex import harness, probpath, tv
from pegrex.linsolve import LinearBackend, LinearError
from pegrex.smt import auto_feasible


@pytest.mark.parametrize("command", [
    "pytest; echo SECOND_COMMAND",
    "pytest && echo SECOND_COMMAND",
    "pytest | tee /tmp/output",
    "pytest $(whoami)",
    "pytest `whoami`",
    "pytest > /tmp/output",
    "pytest\nwhoami",
])
def test_shell_allow_rule_cannot_authorize_command_injection(command):
    verdict = harness.check_action({"tool": "shell", "args": command},
                                   harness.default_policy())
    assert verdict["verdict"] == "refused"


def test_structured_shell_argv_is_the_authorized_identity():
    allowed = harness.check_action({"tool": "shell", "argv": ["pytest", "-q"]},
                                   harness.default_policy())
    assert allowed["verdict"] == "allowed" and allowed["argv"] == ["pytest", "-q"]
    assert harness.check_action({"tool": "shell", "argv": ["pytest;"]},
                                harness.default_policy())["verdict"] == "refused"
    assert harness.check_action({"tool": "shell", "argv": ["git", "push"]},
                                harness.default_policy())["verdict"] == "refused"


def test_missing_z3_is_unknown_not_discarded_atom_success(monkeypatch):
    real_import = builtins.__import__
    def without_z3(name, *args, **kwargs):
        if name == "z3":
            raise ImportError("test: no z3")
        return real_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", without_z3)
    assert auto_feasible(["(x < y)", "(y < x)"]) is None


def test_z3_multi_variable_contradiction_is_decided():
    assert auto_feasible(["(x < y)", "(y < x)"]) is False


def test_fractional_integer_atoms_refuse_instead_of_shifting_bounds():
    backend = LinearBackend()
    for atom in ("(x < 1/2)", "(1/2*x <= 1)"):
        with pytest.raises(LinearError, match="fractional atom"):
            backend.learn([atom])


def test_probpath_distinguishes_outcomes_and_reports_ambiguous_legacy_traces():
    contracts = [(frozenset({"(n > 0)"}), "1"),
                 (frozenset({"(n > 0)"}), "2")]
    fitted = probpath.fit(contracts, [set(["(n > 0)"])])
    assert fitted["ambiguous_runs"] == 1
    assert [row["count"] for row in fitted["paths"]] == [0, 0]
    assert all(0 <= row["frequency"] <= 1 for row in fitted["paths"])
    observed = probpath.fit(contracts, [
        {"constraints": {"(n > 0)"}, "outcome": "2"}])
    assert [row["count"] for row in observed["paths"]] == [0, 1]


def test_legacy_unconfirmed_difference_is_unknown():
    assert tv.wrap({"verified": False, "counterexample": None,
                    "note": "no confirmed witness"})["verdict"] == tv.UNKNOWN
    assert tv.wrap({"verified": False, "counterexample": {"inputs": {"x": 1}}
                    })["verdict"] == tv.REFUTED


def test_raw_shell_text_is_refused_even_without_metacharacters():
    verdict = harness.check_action({"tool": "shell", "args": "pytest -q"},
                                   harness.default_policy())
    assert verdict["verdict"] == "refused"
    assert "structured argv" in verdict["reason"]


@pytest.mark.parametrize("argv", [
    ["pytest", "safe;whoami"],
    ["pytest", "'$(whoami)'"],
    ["pytest", "$HOME/tests"],
    ["pytest", "%PATH%\\tests"],
    ["pytest", "!PATH!\\tests"],
    ["/usr/bin/pytest"],
    ["C:\\tools\\pytest.exe"],
    ["pytest", "/tmp/tests"],
    ["pytest", "~/tests"],
    ["env", "pytest"],
    ["ｐｙｔｅｓｔ"],
    ["рytest"],
])
def test_argv_policy_refuses_execution_and_path_ambiguity(argv):
    assert harness.check_action({"tool": "shell", "argv": argv},
                                harness.default_policy())["verdict"] == "refused"


def test_alternate_executable_names_share_one_authorized_identity():
    for executable in ("pytest", "pytest.exe", "py.test"):
        verdict = harness.check_action({"tool": "shell", "argv": [executable, "-q"]},
                                       harness.default_policy())
        assert verdict["verdict"] == "allowed"
        assert verdict["argv"] == ["pytest", "-q"]
    assert harness.check_action({"tool": "shell", "argv": ["git.exe", "push"]},
                                harness.default_policy())["verdict"] == "refused"


def test_path_policy_refuses_absolute_traversal_confusable_and_symlinks(tmp_path):
    policy = [{"effect": "allow", "tool": "write", "path": "src/*"}]
    for path in ("/tmp/secret", "C:\\secret", "src/../secret",
                 "src\\..\\secret", "src/ｓecret"):
        verdict = harness.check_action({"tool": "write", "path": path},
                                       policy, base_dir=tmp_path)
        assert verdict["verdict"] == "refused", path
    (tmp_path / "src").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (tmp_path / "src" / "link").symlink_to(outside, target_is_directory=True)
    verdict = harness.check_action({"tool": "write", "path": "src/link/secret"},
                                   policy, base_dir=tmp_path)
    assert verdict["verdict"] == "refused"
    assert "symbolic-link" in verdict["reason"]
    allowed = harness.check_action({"tool": "write", "path": "src/app.py"},
                                   policy, base_dir=tmp_path)
    assert allowed["verdict"] == "allowed" and allowed["path"] == "src/app.py"
