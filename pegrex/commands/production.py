"""Production core-operation and Tools API command surface."""
from __future__ import annotations

import json
from pathlib import Path

from .common import _emit_json


def _arguments(args):
    if args.input_file:
        text = Path(args.input_file).read_text(encoding="utf-8")
    elif args.input:
        text = args.input
        if text.startswith("@"):
            text = Path(text[1:]).read_text(encoding="utf-8")
    else:
        text = "{}"
    value = json.loads(text)
    if not isinstance(value, dict):
        raise ValueError("--input must contain a JSON object")
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

    envelope = invoke(args.name, _arguments(args), workspace=args.workspace)
    _emit_json(envelope)
    return _exit_code(envelope, args.fail_on_unknown)


def _cmd_engine(args):
    from ..core import get_engine

    engine = get_engine()
    if args.operation == "list":
        _emit_json(engine.operations())
        return 0
    result = engine.execute(args.operation, _arguments(args))
    envelope = result.to_dict()
    _emit_json(envelope)
    if result.status.value == "error":
        return 1
    if args.fail_on_unknown and (result.verdict is not None
                                 and result.verdict.value == "unknown"):
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
    source = tool.add_mutually_exclusive_group()
    source.add_argument("--input", help="JSON object, or @path/to/input.json")
    source.add_argument("--input-file")
    tool.add_argument("--fail-on-unknown", action="store_true")
    tool.set_defaults(fn=_cmd_tool)

    engine = subparsers.add_parser(
        "engine", help="invoke a structured CoreEngine operation (or 'list')")
    engine.add_argument("operation")
    source = engine.add_mutually_exclusive_group()
    source.add_argument("--input", help="JSON object, or @path/to/input.json")
    source.add_argument("--input-file")
    engine.add_argument("--fail-on-unknown", action="store_true")
    engine.set_defaults(fn=_cmd_engine)
