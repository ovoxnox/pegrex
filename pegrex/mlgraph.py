"""
mlgraph - ML graph verification after quantization/pruning

A graph is a list of ops [{op, inputs, weights, bias, out}]. Quantization
attaches (scale, zero_point) per tensor; pruning drops near-zero weights.
Output equivalence is checked by INTERVAL BOUNDS (pegrex.intervals):
the quant error path builds an error graph -- each quantized tensor gets
an additive [-s/2, s/2] representational error, propagated through the
ops by sound interval arithmetic -- and the bound is read off the final
error interval. Concrete numeric simulation confirms the bound on
sampled inputs. Outside the linear fragment: loud refusal, never a
guess. Every claim is bounded: only the input_ranges / samples given are
concluded about, nothing beyond them."""

from __future__ import annotations

import math

from . import intervals
from .intervals import Interval, IntervalError


class MLGraphError(ValueError):
    pass


def simulate(graph, inputs):
    """Concrete forward pass (add/mul/linear/relu only)."""
    env = dict(inputs)
    for node in graph:
        op = node["op"]
        ins = [env[i] for i in node["inputs"]]
        if op == "add":
            env[node["out"]] = ins[0] + ins[1]
        elif op == "mul":
            env[node["out"]] = ins[0] * ins[1]
        elif op == "linear":
            w = node["weights"]
            b = node["bias"]
            xs = ins[0] if len(ins) == 1 and isinstance(ins[0], list) else ins
            env[node["out"]] = sum(wi * xi for wi, xi in zip(w, xs)) + b
        elif op == "relu":
            x = ins[0]
            env[node["out"]] = [max(0, v) for v in x] if isinstance(x, list) \
                else max(0, x)
        else:
            raise MLGraphError(f"mlgraph: unsupported op {op!r}")
    return env


# ---------------------------------------------------------------------------
# Quantization error bounds: interval arithmetic over an error graph
# ---------------------------------------------------------------------------

def _quant_error_graph(graph, quantized):
    """Mirror `graph` as an error graph: values are intervals for the
    quantization error of each tensor. Exact inputs carry [0, 0]; every
    quantized tensor gains an additive [-s/2, s/2] (representational
    error of rounding to scale s); ops propagate errors:

      linear -> sum(w_i * err_i)          (exact for linear error terms)
      add    -> err_a + err_b             (exact)
      relu   -> err * [-1, 1]             (1-Lipschitz nonexpansiveness:
                                           |relu(a)-relu(b)| <= |a-b|, so
                                           the output error lies in
                                           [-maxabs(err_in), +maxabs])
      mul    -> only sound when both input errors are exactly [0, 0]
               (checked after propagation; otherwise loud refusal --
               bounding a product error needs value ranges)

    Every step is an inclusion-sound interval op, so the final interval
    encloses every real quantization-error realization."""
    nodes = []
    seeds = {}
    for idx, node in enumerate(graph):
        op = node["op"]
        if "out" not in node:
            raise MLGraphError(f"mlgraph: node {idx} has no 'out'")
        out = node["out"]
        if op == "linear":
            w = node.get("weights")
            if w is None:
                raise MLGraphError(f"mlgraph: linear node {out!r} needs "
                                   f"'weights'")
            ins = list(node.get("inputs", []))
            if len(ins) == 1:
                # sole input denotes the feature vector (simulate() takes
                # it as a list): expand to per-component error names
                ins = [f"__err_{ins[0]}#{j}" for j in range(len(w))]
                for n in ins:
                    seeds[n] = Interval(0, 0)
            elif len(ins) == len(w):
                for n in ins:
                    seeds.setdefault(n, Interval(0, 0))
            else:
                raise MLGraphError(f"mlgraph: linear node {out!r} arity "
                                   f"mismatch: {len(w)} weights vs "
                                   f"{len(ins)} inputs")
            nodes.append({"op": "linear", "inputs": ins, "weights": w,
                          "bias": 0, "out": out})
        elif op == "add":
            nodes.append({"op": "add", "inputs": list(node["inputs"]),
                          "out": out})
            for n in node["inputs"]:
                seeds.setdefault(n, Interval(0, 0))
        elif op == "mul":
            nodes.append({"op": "mul", "inputs": list(node["inputs"]),
                          "out": out})
            for n in node["inputs"]:
                seeds.setdefault(n, Interval(0, 0))
        elif op == "relu":
            lip = f"__lip_{idx}"
            nodes.append({"op": "const", "value": Interval(-1, 1),
                          "inputs": [], "out": lip})
            nodes.append({"op": "mul", "inputs": [node["inputs"][0], lip],
                          "out": out, "__lip__": True})
            seeds.setdefault(node["inputs"][0], Interval(0, 0))
        else:
            raise MLGraphError(f"mlgraph: unsupported op {op!r}")
        if out in quantized:
            s = quantized[out]
            qv = f"__qerr_{idx}"
            nodes.append({"op": "const", "value": Interval(-s / 2.0, s / 2.0),
                          "inputs": [], "out": qv})
            nodes.append({"op": "add", "inputs": [out, qv], "out": out})
    return nodes, seeds


def quant_error_bound(graph, quantized, input_ranges=None,
                      method="intervals") -> float:
    """Worst-case output error bound for the quantized graph.

    method="intervals" (default): delegates to pegrex.intervals -- an
    error graph is propagated with sound interval arithmetic and the
    bound is max_abs of the final error interval. For a single linear
    output tensor with scale s this coincides with the certified m123
    figure s/2, and it stays sound through linear/add/relu chains.
    method="legacy": the retired scale-summing heuristic
    (sum of s/2 over quantized tensors), kept only for comparisons.

    The bound is a bounded-input claim: it covers the graph as specified
    and says nothing about inputs or graphs beyond it."""
    if method == "legacy":
        bound = 0.0
        scales = dict(quantized)
        for node in graph:
            if node["out"] in scales:
                bound += scales[node["out"]] / 2.0
        return bound
    if method != "intervals":
        raise MLGraphError(f"mlgraph: unknown bound method {method!r}")
    err_graph, seeds = _quant_error_graph(graph, dict(quantized))
    try:
        env = intervals.propagate(err_graph, seeds)
    except IntervalError as e:
        raise MLGraphError(f"mlgraph: {e}") from e
    zero = Interval(0, 0)
    for node in err_graph:  # mul soundness post-check
        if node["op"] == "mul" and not node.get("__lip__"):
            ins = node["inputs"]
            if any(env[i] != zero for i in ins):
                raise MLGraphError(
                    f"mlgraph: cannot bound product error at {node['out']!r} "
                    f"without value ranges -- refusing")
    if not graph:
        raise MLGraphError("mlgraph: empty graph -- nothing to bound")
    r = env[graph[-1]["out"]]
    rs = r if isinstance(r, list) else [r]
    mags = [e.max_abs for e in rs]
    if any(m is None for m in mags):
        return math.inf
    return float(max(mags))


def check_equivalence(graph_float, graph_quant, inputs_list,
                      quantized, eps, method="intervals", input_ranges=None):
    """Float vs quantized graph: the interval error bound must be within
    eps and concrete simulation must agree within eps on every sample.

    The bound now comes from interval arithmetic (see quant_error_bound);
    with input_ranges given, the exact float-vs-quant difference
    expression is bounded via intervals.bound_equivalence and the worst
    of the two sound bounds is used. A refused interval check raises
    MLGraphError loudly -- never silently skipped. All verdicts are
    bounded claims: they conclude nothing about inputs outside
    input_ranges / inputs_list."""
    bound = quant_error_bound(graph_quant, quantized, method=method)
    if bound > eps:
        return {"verdict": "refuted",
                "reason": f"error bound {bound:.4f} exceeds eps {eps}",
                "bound": bound}
    if input_ranges is not None:
        be = intervals.bound_equivalence(graph_float, graph_quant,
                                         input_ranges)
        if be["verdict"] == "refused":
            raise MLGraphError(f"mlgraph: interval equivalence refused: "
                               f"{be['reason']}")
        iv = be.get("error_interval")
        if iv is not None:
            exact = iv.max_abs
            if exact is None:
                raise MLGraphError("mlgraph: unbounded error interval -- "
                                   "refusing to claim equivalence beyond "
                                   "bounded inputs")
            bound = max(bound, float(exact))
            if bound > eps:
                return {"verdict": "refuted",
                        "reason": f"error bound {bound:.4f} exceeds eps "
                                  f"{eps}",
                        "bound": bound}
    out_f = graph_float[-1]["out"]
    out_q = graph_quant[-1]["out"]
    for inp in inputs_list:
        ef = simulate(graph_float, dict(inp))[out_f]
        eq = simulate(graph_quant, dict(inp))[out_q]
        if abs(ef - eq) > eps:
            return {"verdict": "refuted",
                    "reason": f"sample divergence {abs(ef - eq):.4f} > {eps}",
                    "inputs": inp}
    return {"verdict": "proved", "bound": bound, "samples": len(inputs_list)}


def prune(weights, threshold):
    """Drop near-zero weights (magnitude < threshold -> 0)."""
    return [0.0 if abs(w) < threshold else w for w in weights]
