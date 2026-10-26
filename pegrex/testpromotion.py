"""Promote confirmed counterexamples into deterministic pytest regressions."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

SCHEMA = "pegrex.test-promotion.v1"
_MISSING = object()


def _validate(function_name: str, counterexample: dict) -> dict:
    if not re.fullmatch(r"[A-Za-z_]\w*", function_name):
        raise ValueError("function_name must be a Python identifier")
    inputs = counterexample.get("inputs")
    if not isinstance(inputs, dict) or any(not re.fullmatch(r"[A-Za-z_]\w*", key)
                                           for key in inputs):
        raise ValueError("counterexample.inputs must be a string-keyed argument mapping")
    if counterexample.get("confirmed") is not True:
        raise ValueError("only a confirmed counterexample can be promoted; missing or false confirmation is unconfirmed")
    return dict(sorted(inputs.items()))


def _write(output: str | Path, identity: dict, test_source: str) -> dict:
    digest = hashlib.sha256(json.dumps(identity, sort_keys=True, default=repr,
                                      separators=(",", ":")).encode()).hexdigest()
    name = f"test_promoted_{digest[:16]}"
    marker = f"# pegrex-counterexample: {digest}"
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    existing = path.read_text(encoding="utf-8") if path.exists() else ""
    if marker in existing:
        return {"schema": SCHEMA, "status": "existing", "path": str(path),
                "test_name": name, "identity": digest}
    source = f"\n\n{marker}\ndef {name}():\n{test_source}"
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(existing.rstrip() + source + "\n", encoding="utf-8")
    temporary.replace(path)
    return {"schema": SCHEMA, "status": "created", "path": str(path),
            "test_name": name, "identity": digest}


def promote_counterexample(counterexample: dict, function_name: str, output: str | Path,
                           *, expected=_MISSING, module: str | None = None) -> dict:
    """Create a regression only with a concrete expected observable result."""
    inputs = _validate(function_name, counterexample)
    if expected is _MISSING:
        raise ValueError("expected is required; an unevaluated expression is not an expected result")
    if module is not None and not re.fullmatch(r"[A-Za-z_]\w*(\.[A-Za-z_]\w*)*", module):
        raise ValueError("module must be a dotted Python module name")
    arguments = ", ".join(f"{key}={value!r}" for key, value in inputs.items())
    if module:
        call = f"__import__({module!r}, fromlist=[{function_name!r}]).{function_name}({arguments})"
    else:
        call = f"{function_name}({arguments})"
    body = f"    assert {call} == {expected!r}\n"
    return _write(output, {"kind": "expected", "function": function_name,
                           "inputs": inputs, "expected": expected, "module": module}, body)


def promote_patch_counterexample(counterexample: dict, function_name: str,
                                 before_path: str | Path, after_path: str | Path,
                                 output: str | Path) -> dict:
    """Generate a differential regression using the pre-patch function as oracle."""
    inputs = _validate(function_name, counterexample)
    before = str(Path(before_path).resolve())
    after = str(Path(after_path).resolve())
    arguments = ", ".join(f"{key}={value!r}" for key, value in inputs.items())
    body = f'''    import types
    from pathlib import Path
    def load(path, module_name):
        # Compile current bytes directly: importlib may reuse a stale pyc when
        # a same-length patch is rewritten within one mtime tick.
        module = types.ModuleType(module_name)
        module.__file__ = path
        exec(compile(Path(path).read_bytes(), path, "exec"), module.__dict__)
        return module
    before = load({before!r}, "pegrex_before_{function_name}")
    after = load({after!r}, "pegrex_after_{function_name}")
    assert before.{function_name}({arguments}) == after.{function_name}({arguments})
'''
    return _write(output, {"kind": "differential", "function": function_name,
                           "inputs": inputs, "before": before, "after": after}, body)
