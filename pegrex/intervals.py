"""
intervals - arithmetic over exact rationals

Bounds are Fractions (stdlib fractions.Fraction); float endpoints are
converted exactly (Fraction(0.1) is the exact binary value, so no
rounding silently widens or narrows a bound). An unbounded side is None:
lo=None means -inf, hi=None means +inf.

Soundness contract: every operator returns an interval that encloses ALL
real results of the corresponding operation on operand values taken from
the operand intervals. + and - are exact images; * takes the min/max of
the four quadrant products; / refuses (IntervalError) when the divisor
interval may contain 0 -- no union-split tricks. relu is the monotone
image [relu(lo), relu(hi)]. Chaining sound ops keeps every intermediate
enclosing, so propagate() output encloses every real execution for the
given input ranges. Equivalence claims are bounded-input claims only:
outside input_ranges nothing is concluded.
"""
from __future__ import annotations

from fractions import Fraction


class IntervalError(ValueError):
    """Outside the certified interval fragment -- loud refusal."""


def _q(v, side: str) -> Fraction | None:
    """Coerce an endpoint to Fraction (None = unbounded, kept as None)."""
    if v is None:
        return None
    if isinstance(v, Fraction):
        return v
    if isinstance(v, bool):
        raise IntervalError(f"intervals: boolean endpoint {v!r} is not numeric")
    if isinstance(v, int):
        return Fraction(v)
    if isinstance(v, float):
        return Fraction(v)          # exact binary value, never rounded
    raise IntervalError(f"intervals: endpoint {v!r} of type {type(v).__name__} "
                        f"is not a number (side {side})")


def _need(lo, hi):
    if lo is not None and hi is not None and lo > hi:
        raise IntervalError(f"intervals: empty range lo={lo} > hi={hi}")


class Interval:
    """Closed interval [lo, hi]; None endpoint = unbounded that side."""

    __slots__ = ("lo", "hi")

    def __init__(self, lo=0, hi=0):
        """  init  (lo, hi): see module docstring."""
        lo = _q(lo, "lo")
        hi = _q(hi, "hi")
        _need(lo, hi)
        self.lo = lo
        self.hi = hi

    def __repr__(self):
        return f"Interval({self.lo}, {self.hi})"

    def __str__(self):
        lo = "-inf" if self.lo is None else str(self.lo)
        hi = "+inf" if self.hi is None else str(self.hi)
        return f"[{lo}, {hi}]"

    def __eq__(self, other):
        return isinstance(other, Interval) and self.lo == other.lo \
            and self.hi == other.hi

    def __hash__(self):
        return hash((self.lo, self.hi))

    # -- basic predicates
    @property
    def is_point(self) -> bool:
        """is point(): see module docstring."""
        return self.lo is not None and self.lo == self.hi

    @property
    def contains_zero(self) -> bool:
        return (self.lo is None or self.lo <= 0) and \
               (self.hi is None or self.hi >= 0)

    @property
    def max_abs(self) -> Fraction:
        """max |x| over the interval; unbounded side -> +inf (None)."""
        cands = []
        for e in (self.lo, self.hi):
            if e is None:
                return None
            cands.append(abs(e))
        return max(cands)

    # -- algebra 
    def __neg__(self):
        return Interval(None if self.hi is None else -self.hi,
                        None if self.lo is None else -self.lo)

    def __add__(self, o):
        o = _coerce(o)
        lo = None if self.lo is None or o.lo is None else self.lo + o.lo
        hi = None if self.hi is None or o.hi is None else self.hi + o.hi
        return Interval(lo, hi)

    __radd__ = __add__

    def __sub__(self, o):
        return self + (-_coerce(o))

    def __rsub__(self, o):
        return _coerce(o) + (-self)

    def __mul__(self, o):
        o = _coerce(o)
        prods = []
        for a in (self.lo, self.hi):
            for b in (o.lo, o.hi):
                if a is None or b is None:
                    return Interval(None, None)   # any unbounded product
                prods.append(a * b)
        return Interval(min(prods), max(prods))

    __rmul__ = __mul__

    def __truediv__(self, o):
        o = _coerce(o)
        if o.contains_zero:
            raise IntervalError(
                f"intervals: division by interval containing zero {o} -- "
                f"refusing union-split refinement")
        # 1/[lo,hi] with a divisor that excludes 0: endpoints same sign
        inv = [Fraction(1) / e for e in (o.lo, o.hi)]
        return self * Interval(min(inv), max(inv))

    def __rtruediv__(self, o):
        return _coerce(o) / self

    def __abs__(self):
        if self.contains_zero:
            return Interval(0, self.max_abs)
        return Interval(min(abs(self.lo), abs(self.hi)),
                        max(abs(self.lo), abs(self.hi)))

    # -- lattice
    def intersection(self, o):
        o = _coerce(o)
        lo = max(x for x in (self.lo, o.lo) if x is not None) \
            if self.lo is not None and o.lo is not None else None
        hi = min(x for x in (self.hi, o.hi) if x is not None) \
            if self.hi is not None and o.hi is not None else None
        _need(lo, hi)
        return Interval(lo, hi)

    def hull(self, o):
        o = _coerce(o)
        los = [x for x in (self.lo, o.lo) if x is not None]
        his = [x for x in (self.hi, o.hi) if x is not None]
        lo = min(los) if los else None
        hi = max(his) if his else None
        return Interval(lo, hi)

    def relu(self):
        """Monotone image: relu([lo,hi]) = [max(lo,0), max(hi,0)] -- exact,
        because relu is monotone nondecreasing."""
        lo = Fraction(0) if self.lo is None else max(self.lo, Fraction(0))
        hi = None if self.hi is None else max(self.hi, Fraction(0))
        return Interval(lo, hi)


def _coerce(v) -> Interval:
    if isinstance(v, Interval):
        return v
    if isinstance(v, (int, float, Fraction)) and not isinstance(v, bool):
        return Interval(v, v)
    raise IntervalError(f"intervals: cannot treat {v!r} as an interval")


def I(lo, hi) -> Interval:
    """Convenience constructor."""
    return Interval(lo, hi)


# ---------------------------------------------------------------------------
# Forward interval evaluation over mlgraph graph schemas
# ---------------------------------------------------------------------------

def _range_to_interval(v) -> Interval:
    if isinstance(v, Interval):
        return v
    if isinstance(v, (int, float, Fraction)) and not isinstance(v, bool):
        return Interval(v, v)
    if isinstance(v, (tuple, list)) and len(v) == 2:
        return Interval(v[0], v[1])
    raise IntervalError(f"intervals: input range {v!r} is not (lo, hi)")


def _linear(node, xs, where):
    w = node.get("weights")
    if w is None:
        raise IntervalError(f"intervals: {where} requires 'weights'")
    if len(xs) != len(w):
        raise IntervalError(f"intervals: {where} arity mismatch: "
                            f"{len(w)} weights vs {len(xs)} inputs")
    acc = Interval(node.get("bias", 0), node.get("bias", 0))
    for wi, xi in zip(w, xs):
        acc = acc + _coerce(wi) * xi
    return acc


def _eval(node, env, where):
    """Evaluate one node over the interval environment (mirrors the exact
    schema mlgraph.simulate() accepts)."""
    op = node.get("op")
    ins = [env[i] for i in node.get("inputs", [])]
    if op == "const":
        if "value" in node:
            v = node["value"]
        elif "const" in node:
            v = node["const"]
        else:
            raise IntervalError(f"intervals: {where} const node needs 'value'")
        if isinstance(v, Interval):
            return v
        if isinstance(v, list):
            return [_range_to_interval(x) for x in v]
        return _range_to_interval(v)
    if op == "add":
        a, b = _bin(ins, where, op)
        if isinstance(a, list) or isinstance(b, list):
            a, b = _vecs(a, b, where)
            return [x + y for x, y in zip(a, b)]
        return a + b
    if op == "mul":
        a, b = _bin(ins, where, op)
        if isinstance(a, list) or isinstance(b, list):
            a, b = _vecs(a, b, where)
            return [x * y for x, y in zip(a, b)]
        return a * b
    if op == "sub":
        a, b = _bin(ins, where, op)
        return a - b
    if op == "linear":
        xs = ins[0] if len(ins) == 1 and isinstance(ins[0], list) else ins
        return _linear(node, xs, where)
    if op == "relu":
        if len(ins) != 1:
            raise IntervalError(f"intervals: relu takes 1 input, got {len(ins)}")
        x = ins[0]
        if isinstance(x, list):
            return [e.relu() for e in x]
        return x.relu()
    raise IntervalError(f"intervals: unsupported op {op!r} -- refusing to "
                        f"silently skip a node")


def _bin(ins, where, op):
    if len(ins) != 2:
        raise IntervalError(f"intervals: {op} takes 2 inputs, got {len(ins)} "
                            f"at {where}")
    a, b = ins
    if isinstance(a, list) != isinstance(b, list):
        raise IntervalError(f"intervals: {op} mixes scalar and vector "
                            f"operands at {where}")
    return a, b


def _vecs(a, b, where):
    if not isinstance(a, list):
        a = [a] * len(b)
    if not isinstance(b, list):
        b = [b] * len(a)
    if len(a) != len(b):
        raise IntervalError(f"intervals: vector length mismatch at {where}")
    return a, b


def propagate(graph, input_ranges) -> dict:
    """Forward interval evaluation.

    graph: the SAME list-of-nodes schema mlgraph.simulate() accepts
           ({op, inputs, weights, bias, out}); nodes evaluate in list
           order, each node's interval result is stored under its "out".
    input_ranges: {name: (lo, hi) | Interval | number} per scalar input,
           or {name: [(lo, hi), ...]} per component for vector inputs.

    Returns {node_name: Interval | [Interval, ...]}.
    Sound by construction: every op's interval result encloses all real
    results for the input ranges, so the output encloses every real
    execution. Claims are bounded: outside input_ranges nothing is
    concluded. Unknown ops raise IntervalError naming the op.
    """
    env = {}
    for k, v in (input_ranges or {}).items():
        env[k] = [_range_to_interval(x) for x in v] if isinstance(v, list) \
            else _range_to_interval(v)
    for idx, node in enumerate(graph):
        if "out" not in node:
            raise IntervalError(f"intervals: node {idx} has no 'out' name")
        env[node["out"]] = _eval(node, env, f"node {node['out']!r}")
    return env


def _structurally_aligned(gf, gq) -> bool:
    """Same node count, same op per position, same inputs per position --
    the shape quantization actually produces (same net, snapped constants)."""
    if len(gf) != len(gq):
        return False
    for nf, nq in zip(gf, gq):
        if nf.get("op") != nq.get("op"):
            return False
        if list(nf.get("inputs", [])) != list(nq.get("inputs", [])):
            return False
        if nf.get("op") == "linear":
            if len(nf.get("weights", [])) != len(nq.get("weights", [])):
                return False
    return True


def _aligned_error_interval(gf, gq, input_ranges) -> Interval:
    """Node-wise (quant - float) difference for structurally aligned graphs.

    V carries the quant graph's value intervals (sound enclosures of its
    real values); D carries the difference intervals. Graph inputs are
    SHARED: V_in is the input range, D_in is exactly [0, 0] (both graphs
    see the same input values -- this is what 'bounded inputs' means).

      linear: d_out = sum(wf_i*d_i) + sum((wq-wf)_i*v_i) + (bq-bf)
              -- exact algebra from v_f = v_q - d; interval-evaluating
              the right side encloses every real (y_q - y_f)(x).
      relu:   relu is 1-Lipschitz: |relu(a)-relu(b)| <= |a-b|, and D_h
              encloses h_q - h_f pointwise, so d_out = [-m, m] with
              m = max_abs(D_h) encloses relu(h_q) - relu(h_f).
      add:    exact;  mul/const: exact;  anything else: loud refusal.

    Linear forms in independent interval variables evaluate exactly, so
    for pure linear chains this bound is tight, not merely sound."""
    V: dict = {}
    D: dict = {}
    for k, v in (input_ranges or {}).items():
        iv = [_range_to_interval(x) for x in v] if isinstance(v, list) \
            else _range_to_interval(v)
        V[k] = iv
        D[k] = [Interval(0, 0) for _ in iv] if isinstance(iv, list) \
            else Interval(0, 0)

    def dmax(d):
        if isinstance(d, list):
            ms = [x.max_abs for x in d]
            return None if any(m is None for m in ms) else max(ms)
        return d.max_abs

    for nf, nq in zip(gf, gq):
        op = nq.get("op")
        ins = list(nq.get("inputs", []))
        out = nq.get("out")
        if out is None:
            raise IntervalError("intervals: node without 'out'")
        if op == "linear":
            wq, wf = nq.get("weights"), nf.get("weights")
            bq = nq.get("bias", 0)
            bf = nf.get("bias", 0)
            if wq is None or wf is None or len(wq) != len(wf):
                raise IntervalError(f"intervals: aligned linear node {out!r} "
                                    f"weight mismatch")
            v_in = [V[i] for i in ins]
            d_in = [D[i] for i in ins]
            if len(ins) == 1 and isinstance(v_in[0], list):
                v_in, d_in = v_in[0], d_in[0]
            if len(v_in) != len(wq):
                raise IntervalError(f"intervals: linear node {out!r} arity "
                                    f"mismatch: {len(wq)} weights vs "
                                    f"{len(v_in)} inputs")
            acc_v = Interval(bq, bq)
            for wi, vi in zip(wq, v_in):
                acc_v = acc_v + _coerce(wi) * vi
            acc_d = Interval(bq - bf, bq - bf)
            for i, (wqf, wff) in enumerate(zip(wq, wf)):
                acc_d = acc_d + _coerce(wff) * d_in[i] \
                    + (_coerce(wqf) - _coerce(wff)) * v_in[i]
            V[out], D[out] = acc_v, acc_d
        elif op == "relu":
            if len(ins) != 1:
                raise IntervalError(f"intervals: relu takes 1 input at {out!r}")
            m = dmax(D[ins[0]])
            V[out] = [x.relu() for x in V[ins[0]]] \
                if isinstance(V[ins[0]], list) else V[ins[0]].relu()
            D[out] = Interval(None, None) if m is None else Interval(-m, m)
        elif op == "add":
            if len(ins) != 2:
                raise IntervalError(f"intervals: add takes 2 inputs at {out!r}")
            V[out] = V[ins[0]] + V[ins[1]]
            D[out] = D[ins[0]] + D[ins[1]]
        elif op == "mul":
            if len(ins) != 2:
                raise IntervalError(f"intervals: mul takes 2 inputs at {out!r}")
            z = Interval(0, 0)
            if D[ins[0]] != z or D[ins[1]] != z:
                raise IntervalError(f"intervals: cannot bound product error "
                                    f"at {out!r} without value ranges -- "
                                    f"refusing")
            V[out] = V[ins[0]] * V[ins[1]]
            D[out] = z
        elif op == "const":
            vq = nq.get("value", nq.get("const"))
            vf = nf.get("value", nf.get("const"))
            if vq is None or vf is None:
                raise IntervalError(f"intervals: const node {out!r} needs "
                                    f"'value' on both graphs")
            V[out] = _range_to_interval(vq)
            D[out] = _range_to_interval(vq) - _range_to_interval(vf)
        else:
            raise IntervalError(f"intervals: unsupported op {op!r} -- "
                                f"refusing to silently skip a node")
    return D[gq[-1].get("out")]


def error_interval(graph_float, graph_quant, input_ranges) -> Interval:
    """Interval for (quant_out - float_out) over the bounded inputs.

    * structurally aligned graphs (same ops, same inputs per position --
      what quantization produces): the difference is propagated node-wise
      against the SHARED input intervals (exact for linear forms,
      Lipschitz-bound for relu). This is the tight classical bound.
    * otherwise: a combined graph evaluates the actual difference
      expression -- both graphs side by side (inputs duplicated per side
      so each sees the same ranges), a final node subtracts the float
      output from the quantized output.

    Interval arithmetic is inclusion-sound op by op, so the resulting
    interval encloses every real value of quant_out - float_out for
    inputs in input_ranges. That is the whole proof; there is no
    sampling and no heuristic. Bounded inputs only: outside
    input_ranges nothing is concluded.
    """
    if not graph_float or not graph_quant:
        raise IntervalError("intervals: empty graph -- nothing to bound")
    if _structurally_aligned(graph_float, graph_quant):
        return _aligned_error_interval(graph_float, graph_quant, input_ranges)
    combo = []
    combo_ranges = {}
    for tag, g in (("f", graph_float), ("q", graph_quant)):
        produced = {n["out"] for n in g}
        used = {i for n in g for i in n.get("inputs", [])}
        for name in used - produced:          # graph inputs, duplicated per
            if name in input_ranges:          # side so each evaluates the
                combo_ranges[f"__{tag}_{name}"] = input_ranges[name]
        for node in g:
            n = dict(node)
            n["out"] = f"__{tag}_{node['out']}"
            n["inputs"] = [f"__{tag}_{i}" for i in node.get("inputs", [])]
            combo.append(n)
    f_out = f"__f_{graph_float[-1]['out']}"
    q_out = f"__q_{graph_quant[-1]['out']}"
    combo.append({"op": "const", "value": -1, "inputs": [], "out": "__mone"})
    combo.append({"op": "mul", "inputs": [q_out, "__mone"], "out": "__qneg"})
    combo.append({"op": "add", "inputs": [f_out, "__qneg"], "out": "__diff"})
    env = propagate(combo, combo_ranges)
    r = env["__diff"]
    if isinstance(r, list):
        raise IntervalError("intervals: graph output is a vector; take the "
                            "componentwise error interval instead")
    return r


def bound_equivalence(graph_float, graph_quant, input_ranges) -> dict:
    """Three-valued equivalence verdict over bounded inputs.

    {"equivalent": True|False|None,
     "error_bound": str,       # the honest interval bound (or refusal)
     "error_interval": Interval|None,   # machine-readable (None if refused)
     "verdict": "proved" | "unknown" | "refused",
     "reason": str}

    proved   -- error_interval is exactly [0, 0]: every input in range
                gives bit-identical outputs (bounded claim, nothing more).
    unknown  -- the interval straddles 0 (bound reported honestly, never
                rounded to a false proof) or is disjoint from 0
                (equivalent=False: outputs provably differ on the whole
                box; still reported as unknown because the verdict
                vocabulary is about the equality claim).
    refused  -- an unsupported op: IntervalError is caught and reported,
                never silently skipped.
    """
    try:
        ei = error_interval(graph_float, graph_quant, input_ranges)
    except IntervalError as e:
        return {"equivalent": None, "error_bound": f"refused: {e}",
                "error_interval": None, "verdict": "refused", "reason": str(e)}
    bound = str(ei)
    if ei == Interval(0, 0):
        return {"equivalent": True, "error_bound": bound,
                "error_interval": ei, "verdict": "proved",
                "reason": "error interval is exactly [0, 0] over the "
                          "bounded inputs"}
    if ei.contains_zero:
        return {"equivalent": None, "error_bound": bound,
                "error_interval": ei, "verdict": "unknown",
                "reason": "error interval straddles 0 -- the bound is "
                          "reported honestly, no equivalence claimed"}
    return {"equivalent": False, "error_bound": bound,
            "error_interval": ei, "verdict": "unknown",
            "reason": "error interval is strictly non-zero -- the graphs "
                      "differ on every input in range"}
