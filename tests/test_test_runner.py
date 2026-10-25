import run_tests


def test_pytest_failure_is_not_masked_by_smoke(monkeypatch):
    monkeypatch.setattr(run_tests.importlib.util, "find_spec", lambda name: object())
    monkeypatch.setattr(run_tests.subprocess, "call", lambda command: 7)
    monkeypatch.setattr(run_tests, "smoke", lambda: (_ for _ in ()).throw(
        AssertionError("smoke fallback must not run")))
    assert run_tests.main([]) == 7


def test_missing_pytest_requires_explicit_smoke(monkeypatch, capsys):
    monkeypatch.setattr(run_tests.importlib.util, "find_spec", lambda name: None)
    assert run_tests.main([]) == 2
    assert "--smoke" in capsys.readouterr().err
