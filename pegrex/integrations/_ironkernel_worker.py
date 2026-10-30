"""Isolated ironkernel/NumPy worker; accepts validated JSON, never Python source."""
from __future__ import annotations

import json
import math
import operator
from pathlib import Path
import sys


def encoded(values):
    import numpy as np
    rows = []
    for value in np.asarray(values, dtype=np.float64).reshape(-1):
        number = float(value)
        if math.isnan(number):
            rows.append({"nonfinite": "nan"})
        elif math.isinf(number):
            rows.append({"nonfinite": "inf" if number > 0 else "-inf"})
        else:
            rows.append(number)
    return rows


def build(node, kernel, np):
    op = node["op"]
    if op == "arg":
        return kernel.arg(node["name"])
    if op == "const":
        return float(node["value"])
    args = [build(row, kernel, np) for row in node.get("args", [])]
    if op == "add": return args[0] + args[1]
    if op == "sub": return args[0] - args[1]
    if op == "mul": return args[0] * args[1]
    if op == "div": return args[0] / args[1]
    if op == "pow": return args[0] ** args[1]
    if op == "neg": return -args[0]
    if op == "where": return kernel.where(*args)
    if op in {"lt", "le", "gt", "ge", "eq", "ne"}:
        operations = {"lt": operator.lt, "le": operator.le, "gt": operator.gt,
                      "ge": operator.ge, "eq": operator.eq, "ne": operator.ne}
        return operations[op](*args)
    return getattr(kernel, op)(*args)


def reference(node, inputs, np):
    op = node["op"]
    if op == "arg": return inputs[node["name"]]
    if op == "const": return float(node["value"])
    args = [reference(row, inputs, np) for row in node.get("args", [])]
    binary = {"add": np.add, "sub": np.subtract, "mul": np.multiply,
              "div": np.divide, "pow": np.power, "lt": np.less, "le": np.less_equal,
              "gt": np.greater, "ge": np.greater_equal, "eq": np.equal, "ne": np.not_equal,
              "atan2": np.arctan2, "min": np.minimum, "max": np.maximum}
    unary = {"neg": np.negative, "abs": np.abs, "sqrt": np.sqrt, "log": np.log,
             "exp": np.exp, "log2": np.log2, "log10": np.log10, "sin": np.sin,
             "cos": np.cos, "tan": np.tan, "floor": np.floor, "ceil": np.ceil}
    if op == "where": return np.where(args[0], args[1], args[2])
    if op in binary: return binary[op](*args)
    return unary[op](*args)


def main() -> int:
    input_path, output_path = map(Path, sys.argv[1:3])
    try:
        import ironkernel
        from ironkernel import kernel, rt
        import numpy as np
        request = json.loads(input_path.read_text(encoding="utf-8"))
        raw_inputs = request["inputs"]
        inputs = {name: (float(value) if isinstance(value, (int, float)) else
                         np.asarray(value, dtype=np.float64))
                  for name, value in raw_inputs.items()}
        expression = build(request["expression"], kernel, np)
        spec = kernel.elementwise(expression)
        bound = {name: (rt.asarray(value) if isinstance(value, np.ndarray) else float(value))
                 for name, value in inputs.items()}
        with np.errstate(all="ignore"):
            expected = reference(request["expression"], inputs, np)
            observed = rt.go(kernel.map(spec, **bound)).result().numpy()
        report = {"schema": "pegrex.ironkernel-worker.v1",
                  "input_sha256": request["input_sha256"],
                  "backend_version": str(ironkernel.__version__),
                  "numpy_version": str(np.__version__),
                  "observed": encoded(observed), "expected": encoded(expected)}
        output_path.write_text(json.dumps(report, allow_nan=False), encoding="utf-8")
        return 0
    except Exception as error:
        output_path.write_text(json.dumps({
            "schema": "pegrex.ironkernel-worker.v1", "status": "error",
            "error": f"{type(error).__name__}: {error}"}), encoding="utf-8")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
