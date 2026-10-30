"""Small, bounded finite-domain semantic proof checker.

The proof establishes equivalence only for every assignment in explicitly
listed finite domains. It does not establish equivalence over all integers or
for arbitrary source programs. The JSON expression language is deliberately
small and interpreted without eval/exec.
"""
from __future__ import annotations

import hashlib
import itertools
import json

SCHEMA = "pegrex.finite-domain-proof.v1"
MAX_VARIABLES = 8
MAX_DOMAIN_VALUES = 64
MAX_ASSIGNMENTS = 100_000
MAX_NODES = 256
MAX_DEPTH = 32
MAX_INTEGER_ABS = 1_000_000_000

_BINARY = {
    "add": lambda a, b: a + b,
    "sub": lambda a, b: a - b,
    "mul": lambda a, b: a * b,
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "lt": lambda a, b: a < b,
    "le": lambda a, b: a <= b,
    "gt": lambda a, b: a > b,
    "ge": lambda a, b: a >= b,
}


def _canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _unknown(reason: str, **details) -> dict:
    return {"schema": SCHEMA, "checked": False, "verdict": "unknown",
            "reason": reason, "details": details}


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _validate_domains(domains):
    if not isinstance(domains, dict) or len(domains) > MAX_VARIABLES:
        raise ValueError("invalid-variable-domain-map")
    normalized = {}
    assignments = 1
    for name, values in domains.items():
        if not isinstance(name, str) or not name.isidentifier() or len(name) > 64:
            raise ValueError("invalid-variable-name")
        if not isinstance(values, list) or not values or len(values) > MAX_DOMAIN_VALUES:
            raise ValueError("invalid-or-oversized-domain")
        if any(not _is_int(v) or abs(v) > MAX_INTEGER_ABS for v in values):
            raise ValueError("domain-values-must-be-bounded-integers")
        if len(set(values)) != len(values):
            raise ValueError("duplicate-domain-value")
        assignments *= len(values)
        if assignments > MAX_ASSIGNMENTS:
            raise ValueError("assignment-bound-exceeded")
        normalized[name] = tuple(values)
    return normalized, assignments


def _validate_expr(expr, names):
    count = 0

    def visit(node, depth):
        nonlocal count
        count += 1
        if count > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError("expression-resource-bound-exceeded")
        if not isinstance(node, dict) or not isinstance(node.get("op"), str):
            raise ValueError("invalid-expression-node")
        op = node["op"]
        if op == "const":
            if set(node) != {"op", "value"} or not _is_int(node["value"]):
                raise ValueError("invalid-integer-constant")
            if abs(node["value"]) > MAX_INTEGER_ABS:
                raise ValueError("constant-out-of-range")
            return
        if op == "var":
            if set(node) != {"op", "name"} or node["name"] not in names:
                raise ValueError("unknown-variable")
            return
        if op == "neg":
            if set(node) != {"op", "arg"}:
                raise ValueError("invalid-negation-shape")
            visit(node["arg"], depth + 1)
            return
        if op == "not":
            if set(node) != {"op", "arg"}:
                raise ValueError("invalid-not-shape")
            visit(node["arg"], depth + 1)
            return
        if op in _BINARY or op in {"and", "or"}:
            if set(node) != {"op", "left", "right"}:
                raise ValueError("invalid-binary-expression-shape")
            visit(node["left"], depth + 1)
            visit(node["right"], depth + 1)
            return
        if op == "ite":
            if set(node) != {"op", "cond", "then", "else"}:
                raise ValueError("invalid-conditional-shape")
            visit(node["cond"], depth + 1)
            visit(node["then"], depth + 1)
            visit(node["else"], depth + 1)
            return
        raise ValueError("unsupported-expression-operator")

    visit(expr, 0)
    return count


def _eval(node, env):
    op = node["op"]
    if op == "const":
        return node["value"]
    if op == "var":
        return env[node["name"]]
    if op == "neg":
        value = _eval(node["arg"], env)
        if not _is_int(value):
            raise ValueError("negation-requires-integer")
        result = -value
    elif op == "not":
        value = _eval(node["arg"], env)
        if not isinstance(value, bool):
            raise ValueError("not-requires-boolean")
        return not value
    elif op in {"and", "or"}:
        left = _eval(node["left"], env)
        if not isinstance(left, bool):
            raise ValueError("logical-operator-requires-booleans")
        if op == "and" and not left:
            return False
        if op == "or" and left:
            return True
        right = _eval(node["right"], env)
        if not isinstance(right, bool):
            raise ValueError("logical-operator-requires-booleans")
        return right
    elif op == "ite":
        cond = _eval(node["cond"], env)
        if not isinstance(cond, bool):
            raise ValueError("conditional-requires-boolean-condition")
        return _eval(node["then"] if cond else node["else"], env)
    else:
        left, right = _eval(node["left"], env), _eval(node["right"], env)
        if op in {"add", "sub", "mul"} and (not _is_int(left) or not _is_int(right)):
            raise ValueError("arithmetic-requires-integers")
        if op in {"lt", "le", "gt", "ge"} and (not _is_int(left) or not _is_int(right)):
            raise ValueError("ordering-comparison-requires-integers")
        if op in {"eq", "ne"} and type(left) is not type(right):
            raise ValueError("equality-comparison-requires-matching-types")
        result = _BINARY[op](left, right)
    if _is_int(result) and abs(result) > MAX_INTEGER_ABS:
        raise ValueError("evaluation-result-out-of-range")
    return result


def check_finite_domain_proof(proof) -> dict:
    """Check exact equivalence over all assignments in finite declared domains."""
    try:
        if not isinstance(proof, dict) or proof.get("schema") != SCHEMA:
            return _unknown("unsupported-proof-schema")
        if proof.get("schema_version") != 1 or proof.get("claim") != "finite-domain-equivalent":
            return _unknown("unsupported-proof-version-or-claim")
        if set(proof) - {"schema", "schema_version", "claim", "domains", "before", "after", "expected_assignments"}:
            return _unknown("unsupported-proof-fields")
        domains, total = _validate_domains(proof.get("domains"))
        names = set(domains)
        before, after = proof.get("before"), proof.get("after")
        before_nodes = _validate_expr(before, names)
        after_nodes = _validate_expr(after, names)
        if proof.get("expected_assignments") not in {None, total}:
            return _unknown("assignment-count-mismatch", expected=total)
        checked = 0
        for values in itertools.product(*(domains[name] for name in domains)):
            env = dict(zip(domains, values))
            left, right = _eval(before, env), _eval(after, env)
            if type(left) is not type(right) or left != right:
                return {"schema": SCHEMA, "checked": True, "verdict": "refuted",
                        "claim": "finite-domain-equivalent", "assignments_checked": checked + 1,
                        "total_assignments": total, "counterexample": env,
                        "before_result": left, "after_result": right,
                        "proof_sha256": hashlib.sha256(_canonical(proof)).hexdigest()}
            checked += 1
        return {"schema": SCHEMA, "checked": True, "verdict": "proved",
                "claim": "finite-domain-equivalent", "assignments_checked": checked,
                "total_assignments": total, "before_nodes": before_nodes,
                "after_nodes": after_nodes,
                "proof_sha256": hashlib.sha256(_canonical(proof)).hexdigest(),
                "checker": "pegrex-finite-domain-enumerator-v1"}
    except (ValueError, TypeError, KeyError, RecursionError, OverflowError) as error:
        return _unknown("malformed-or-out-of-fragment-proof", error=str(error)[:200])
