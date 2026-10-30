"""Small, deterministic JSON-shape validator shared by public API boundaries.

This implements only the JSON Schema subset emitted by PegRex manifests. It
fails closed on unsupported types and never coerces caller input.
"""
from __future__ import annotations

import math
from typing import Any


_JSON_CONTAINERS = {"object": dict, "array": list, "string": str, "boolean": bool}


def matches_type(value: Any, expected: str | list[str]) -> bool:
    """Return whether *value* has one of the declared JSON primitive types."""
    if isinstance(expected, list):
        return any(matches_type(value, item) for item in expected)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return (isinstance(value, (int, float)) and not isinstance(value, bool)
                and (not isinstance(value, float) or math.isfinite(value)))
    if expected == "null":
        return value is None
    if expected not in _JSON_CONTAINERS:
        raise ValueError(f"unsupported JSON shape type {expected!r}")
    return isinstance(value, _JSON_CONTAINERS[expected])


def _effective_type(name: str, value: Any, definition: dict[str, Any]) -> Any:
    if not isinstance(definition, dict):
        raise TypeError("JSON shape definition must be an object")
    expected = definition.get("type")
    if expected and not matches_type(value, expected):
        raise ValueError(f"argument {name!r} must be {expected}")
    if isinstance(expected, list):
        return next((item for item in expected if matches_type(value, item)), None)
    return expected


def _validate_number(name: str, value: Any, definition: dict[str, Any]) -> None:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError(f"argument {name!r} must be a finite JSON number")
    minimum = definition.get("minimum")
    maximum = definition.get("maximum")
    if minimum is not None and value < minimum:
        raise ValueError(f"argument {name!r} is below its minimum {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"argument {name!r} exceeds its maximum {maximum}")


def _validate_string(name: str, value: str, definition: dict[str, Any]) -> None:
    if len(value) < definition.get("minLength", 0):
        raise ValueError(f"argument {name!r} is shorter than its minimum length")
    max_length = definition.get("maxLength")
    if max_length is not None and len(value) > max_length:
        raise ValueError(f"argument {name!r} exceeds its maximum length")


def _validate_array(name: str, value: list[Any], definition: dict[str, Any]) -> None:
    if len(value) < definition.get("minItems", 0):
        raise ValueError(f"argument {name!r} has too few items")
    max_items = definition.get("maxItems")
    if max_items is not None and len(value) > max_items:
        raise ValueError(f"argument {name!r} has too many items")
    item_schema = definition.get("items")
    if isinstance(item_schema, dict):
        for index, item in enumerate(value):
            validate_value(f"{name}[{index}]", item, item_schema)


def _validate_fields(name: str, value: dict[str, Any], definition: dict[str, Any]) -> None:
    properties = definition.get("properties", {})
    missing = [key for key in definition.get("required", []) if key not in value]
    if missing:
        raise ValueError(
            f"argument {name!r} is missing required field(s): {', '.join(missing)}")
    additional = definition.get("additionalProperties", True)
    extra = sorted(set(value) - set(properties))
    if extra and additional is False:
        raise ValueError(f"argument {name!r} has unknown field(s): {', '.join(extra)}")
    for key, item in value.items():
        if key in properties:
            validate_value(f"{name}.{key}", item, properties[key])
        elif isinstance(additional, dict):
            validate_value(f"{name}.{key}", item, additional)


def validate_value(name: str, value: Any, definition: dict[str, Any]) -> None:
    """Validate one value against a bounded PegRex JSON-shape definition."""
    effective_type = _effective_type(name, value, definition)
    if effective_type in ("integer", "number") and not isinstance(value, bool):
        _validate_number(name, value, definition)
    elif effective_type == "string":
        _validate_string(name, value, definition)
    if "enum" in definition and value not in definition["enum"]:
        raise ValueError(f"argument {name!r} is not one of the allowed values")
    if effective_type == "array":
        _validate_array(name, value, definition)
    elif effective_type == "object":
        _validate_fields(name, value, definition)


def validate_object(arguments: Any, schema: dict[str, Any]) -> None:
    """Validate one complete operation argument object, including unknown keys."""
    if not isinstance(arguments, dict):
        raise ValueError("operation arguments must be a JSON object")
    properties = schema.get("properties", {})
    unknown = sorted(set(arguments) - set(properties))
    if unknown and schema.get("additionalProperties") is False:
        raise ValueError(f"unknown operation argument(s): {', '.join(unknown)}")
    missing = [name for name in schema.get("required", []) if name not in arguments]
    if missing:
        raise ValueError(f"missing required operation argument(s): {', '.join(missing)}")
    for name, value in arguments.items():
        if name in properties:
            validate_value(name, value, properties[name])
