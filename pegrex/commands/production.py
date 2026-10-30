"""Production core-operation and Tools API command surface."""
from __future__ import annotations

import json
from pathlib import Path

from .common import _emit_json
from ..requestlimits import MAX_REQUEST_BYTES, validate_request


def _read_json_input(path: str) -> str:
    """Read at most one byte beyond the public request budget, then decode UTF-8."""
    with Path(path).open("rb") as stream:
        payload = stream.read(MAX_REQUEST_BYTES + 1)
    if len(payload) > MAX_REQUEST_BYTES:
        raise ValueError(f"JSON input exceeds {MAX_REQUEST_BYTES} UTF-8 bytes")
    return payload.decode("utf-8")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Build a JSON object while rejecting ambiguous duplicate keys."""
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    """Reject Python's non-standard NaN and Infinity JSON extensions."""
    raise ValueError(f"non-finite JSON number {value!r} is not supported")


def _arguments(args):
    """Load one bounded, strict JSON object for CoreEngine or Tools API dispatch."""
    if args.input_file:
        text = _read_json_input(args.input_file)
    elif args.input is not None:
        text = args.input
        if text.startswith("@"):
            text = _read_json_input(text[1:])
        elif len(text.encode("utf-8")) > MAX_REQUEST_BYTES:
            raise ValueError(f"JSON input exceeds {MAX_REQUEST_BYTES} UTF-8 bytes")
    else:
        text = "{}"
    value = json.loads(text, object_pairs_hook=_unique_object,
                       parse_constant=_reject_json_constant)
    if not isinstance(value, dict):
        raise ValueError("--input must contain a JSON object")
    validate_request(value)
    return value


def _exit_code(envelope, fail_on_unknown=False):
    if envelope["status"] == "error":
        return 1
    if fail_on_unknown and (envelope.get("verdict") == "unknown"
                            or envelope["status"] == "partial"):
        return 2
    return 0


def _cmd_tools(args):
    from ..toolsapi import list_tools

    manifest = list_tools()
    if args.name:
        rows = [row for row in manifest["tools"] if row["name"] == args.name]
        if not rows:
            raise ValueError(f"unknown tool {args.name!r}")
        _emit_json(rows[0])
    else:
        _emit_json(manifest)
    return 0


def _cmd_tool(args):
    from ..toolsapi import invoke

    envelope = invoke(args.name, _arguments(args), workspace=args.workspace,
                      disclose_errors=True, state=getattr(args, "state", None))
    _emit_json(envelope)
    return _exit_code(envelope, args.fail_on_unknown)


def _cmd_engine(args):
    from ..core import get_engine

    engine = get_engine()
    if args.operation == "list":
        _emit_json(engine.operations())
        return 0
    result = engine.execute(args.operation, _arguments(args), disclose_errors=True,
                            state=getattr(args, "state", None))
    envelope = result.to_dict()
    _emit_json(envelope)
    if result.status.value == "error":
        return 1
    if args.fail_on_unknown and (result.status.value == "partial"
                                 or (result.verdict is not None
                                     and result.verdict.value == "unknown")):
        return 2
    return 0


def register_commands(subparsers):
    """Register the v2 API without changing legacy command output contracts."""
    tools = subparsers.add_parser(
        "tools", help="list the versioned Tools API v2 manifest")
    tools.add_argument("--name", help="show one tool's JSON schema")
    tools.set_defaults(fn=_cmd_tools)

    tool = subparsers.add_parser(
        "tool", help="invoke a workspace-confined Tools API v2 operation")
    tool.add_argument("name")
    tool.add_argument("--workspace", default=".")
    tool.add_argument("--state", choices=("alpha", "demo", "beta"),
                      help="enforce an explicit PegRex lifecycle profile")
    source = tool.add_mutually_exclusive_group()
    source.add_argument("--input", help="JSON object, or @path/to/input.json")
    source.add_argument("--input-file")
    tool.add_argument("--fail-on-unknown", action="store_true")
    tool.set_defaults(fn=_cmd_tool)

    engine = subparsers.add_parser(
        "engine", help="invoke a structured CoreEngine operation (or 'list')")
    engine.add_argument("operation")
    engine.add_argument("--state", choices=("alpha", "demo", "beta"),
                         help="enforce an explicit PegRex lifecycle profile")
    source = engine.add_mutually_exclusive_group()
    source.add_argument("--input", help="JSON object, or @path/to/input.json")
    source.add_argument("--input-file")
    engine.add_argument("--fail-on-unknown", action="store_true")
    engine.set_defaults(fn=_cmd_engine)

    state = subparsers.add_parser("state", help="inspect production lifecycle profiles")
    state_sub = state.add_subparsers(dest="state_command", metavar="<operation>", required=True)
    state_list = state_sub.add_parser("list", help="list alpha, demo, and beta profiles")
    def _state_list(_args):
        from ..states import list_profiles
        _emit_json(list_profiles())
        return 0
    state_list.set_defaults(fn=_state_list)
    state_show = state_sub.add_parser("show", help="show one lifecycle profile")
    state_show.add_argument("name", choices=("alpha", "demo", "beta"))
    def _state_show(args):
        from ..states import get_profile
        _emit_json(get_profile(args.name).to_dict())
        return 0
    state_show.set_defaults(fn=_state_show)
