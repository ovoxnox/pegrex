"""Uniform, deterministic JSON request budgets for public API boundaries."""
from __future__ import annotations

import json
import math
from typing import Any

MAX_REQUEST_BYTES = 4_000_000
MAX_NESTING_DEPTH = 32
MAX_LIST_ITEMS = 2_000
MAX_OBJECT_ITEMS = 2_000
MAX_STRING_CHARS = 2_000_000
MAX_TOTAL_NODES = 100_000
MAX_INTEGER_BITS = 4_096


class RequestBudgetError(ValueError):
    """A request exceeds a public API budget or contains non-JSON values."""


def _json_bytes(value: Any) -> bytes:
    try:
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as error:
        raise RequestBudgetError(
            "request must contain finite JSON-compatible values") from error


def _check_scalar(value: Any) -> None:
    if isinstance(value, str) and len(value) > MAX_STRING_CHARS:
        raise RequestBudgetError("request string-length limit exceeded")
    if (isinstance(value, int) and not isinstance(value, bool)
            and value.bit_length() > MAX_INTEGER_BITS):
        raise RequestBudgetError("request integer magnitude limit exceeded")
    if isinstance(value, float) and not math.isfinite(value):
        raise RequestBudgetError("request numbers must be finite")
    if value is None or isinstance(value, (str, int, float, bool)):
        return
    if not isinstance(value, (list, dict)):
        raise RequestBudgetError("request must contain JSON-compatible values")


def _children(value: Any, depth: int) -> list[tuple[Any, int]]:
    if isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            raise RequestBudgetError("request list-length limit exceeded")
        return [(item, depth + 1) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_OBJECT_ITEMS:
            raise RequestBudgetError("request object-size limit exceeded")
        rows = []
        for key, item in value.items():
            if not isinstance(key, str):
                raise RequestBudgetError("request object keys must be strings")
            if len(key) > 1024:
                raise RequestBudgetError("request object-key length limit exceeded")
            rows.extend(((key, depth + 1), (item, depth + 1)))
        return rows
    return []


def validate_request(value: Any) -> None:
    """Reject oversized, deeply nested, cyclic, or non-finite JSON-shaped input."""
    if len(_json_bytes(value)) > MAX_REQUEST_BYTES:
        raise RequestBudgetError("request size limit exceeded")
    stack = [(value, 0)]
    nodes = 0
    while stack:
        current, depth = stack.pop()
        nodes += 1
        if nodes > MAX_TOTAL_NODES:
            raise RequestBudgetError("request item-count limit exceeded")
        if depth > MAX_NESTING_DEPTH:
            raise RequestBudgetError("request nesting-depth limit exceeded")
        _check_scalar(current)
        stack.extend(_children(current, depth))


def _bounded_integer(arguments: dict[str, Any], name: str, minimum: int,
                     maximum: int) -> None:
    if name not in arguments:
        return
    value = arguments[name]
    if (not isinstance(value, int) or isinstance(value, bool)
            or not minimum <= value <= maximum):
        raise RequestBudgetError(
            f"{name} must be an integer between {minimum} and {maximum}")


def validate_operation_budgets(arguments: Any) -> None:
    """Enforce shared operation budgets before any backend or parser executes."""
    if not isinstance(arguments, dict):
        return
    from .limits import MAX_SOURCE_BYTES
    source = arguments.get("source")
    if isinstance(source, str) and len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
        raise RequestBudgetError(
            f"source input exceeds {MAX_SOURCE_BYTES} UTF-8 bytes")
    _bounded_integer(arguments, "timeout_ms", 1, 300_000)
    _bounded_integer(arguments, "memory_mb", 16, 4096)
    _bounded_integer(arguments, "max_elements", 1, 100_000)
    _bounded_integer(arguments, "max_results", 0, 10_000)
    for name in ("backend_argv", "check_argv", "argv"):
        value = arguments.get(name)
        if value is None:
            continue
        if (not isinstance(value, list) or len(value) > 128
                or any(not isinstance(item, str) or not item or len(item) > 4096
                       for item in value)):
            raise RequestBudgetError(
                f"{name} must be a bounded array of non-empty strings")
