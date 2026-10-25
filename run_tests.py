#!/usr/bin/env python
"""Run the full pytest suite, or an explicitly limited smoke mode."""
from __future__ import annotations

import importlib
import importlib.util
import pathlib
import subprocess
import sys


def smoke() -> int:
    """Run zero-argument tests without pytest; never claim full-suite parity."""
    print("SMOKE MODE: fixtures, parametrization, and pytest hooks are not run.")
    failures = 0
    root = pathlib.Path(__file__).parent
    sys.path.insert(0, str(root))
    for path in sorted((root / "tests").glob("test_*.py")):
        modname = f"tests.{path.stem}"
        try:
            mod = importlib.import_module(modname)
        except Exception as exc:
            failures += 1
            print(f"FAIL {modname}: import error: {exc!r}")
            continue
        for name in sorted(dir(mod)):
            if not name.startswith("test_"):
                continue
            func = getattr(mod, name)
            if not callable(func) or getattr(func, "__code__", None) is None:
                continue
            if func.__code__.co_argcount:
                print(f"SKIP {modname}.{name}: requires pytest fixtures")
                continue
            try:
                func()
                print(f"PASS {modname}.{name}")
            except Exception as exc:
                failures += 1
                print(f"FAIL {modname}.{name}: {exc!r}")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args == ["--smoke"]:
        return smoke()
    if args:
        print(f"usage: {pathlib.Path(sys.argv[0]).name} [--smoke]", file=sys.stderr)
        return 2
    if not importlib.util.find_spec("pytest"):
        print("pytest is required for the full suite; install pegrex[test] "
              "or use --smoke for the explicitly limited runner.", file=sys.stderr)
        return 2
    return subprocess.call([sys.executable, "-m", "pytest", "tests/", "-q",
                            "--tb=short"])


if __name__ == "__main__":
    sys.exit(main())
