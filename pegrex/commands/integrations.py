"""CLI adapters for optional external generation and execution backends."""
from __future__ import annotations

import json
from pathlib import Path

from .common import _emit_json
from .production import _exit_code


def _json_value(text):
    if text.startswith("@"):
        text = Path(text[1:]).read_text(encoding="utf-8")
    return json.loads(text)


def _common(parser):
    parser.add_argument("--workspace", default=".")
    parser.add_argument("--state", choices=("alpha", "demo", "beta"),
                        help="enforce an explicit PegRex lifecycle profile")
    parser.add_argument("--fail-on-unknown", action="store_true")
    parser.add_argument("--timeout-ms", type=int)
    parser.add_argument("--memory-mb", type=int)


def _invoke(args):
    from ..toolsapi import invoke
    values = vars(args).copy()
    tool = values.pop("integration_tool")
    for key in ("fn", "command", "integration_command", "workspace", "fail_on_unknown", "state"):
        values.pop(key, None)
    for key in ("expression", "inputs", "backend_argv", "check_argv", "argv", "files"):
        if values.get(key) is not None:
            values[key] = _json_value(values[key])
    values = {key: value for key, value in values.items() if value is not None}
    envelope = invoke(tool, values, workspace=args.workspace, state=getattr(args, "state", None))
    _emit_json(envelope)
    return _exit_code(envelope, args.fail_on_unknown)


def register_commands(subparsers):
    neural = subparsers.add_parser("neural", help="offline constrained Rust candidate generation")
    nested = neural.add_subparsers(dest="integration_command", metavar="<operation>", required=True)
    generate = nested.add_parser("generate", help="generate a candidate into confined staging")
    generate.add_argument("spec_path")
    generate.add_argument("staging")
    generate.add_argument("--backend-argv", required=True, help="argv JSON array, or @file")
    _common(generate)
    generate.set_defaults(fn=_invoke, integration_tool="neural.generate")
    verify = nested.add_parser("verify", help="independently inspect a staged candidate")
    verify.add_argument("candidate_root")
    verify.add_argument("--check-argv", help="sandboxed compilation argv JSON array, or @file")
    _common(verify)
    verify.set_defaults(fn=_invoke, integration_tool="neural.verify_candidate")

    iron = subparsers.add_parser("ironkernel", help="bounded parallel numerical execution")
    nested = iron.add_subparsers(dest="integration_command", metavar="<operation>", required=True)
    for name, tool in (("run", "ironkernel.run"), ("differential", "ironkernel.differential")):
        command = nested.add_parser(name)
        command.add_argument("expression", help="expression JSON object, or @file")
        command.add_argument("inputs", help="input JSON object, or @file")
        command.add_argument("--max-elements", type=int)
        if name == "differential":
            command.add_argument("--atol", type=float)
            command.add_argument("--rtol", type=float)
        _common(command)
        command.set_defaults(fn=_invoke, integration_tool=tool)

    pythoc = subparsers.add_parser("pythoc", help="sandboxed native compilation and LLVM analysis")
    nested = pythoc.add_subparsers(dest="integration_command", metavar="<operation>", required=True)
    compile_command = nested.add_parser("compile")
    compile_command.add_argument("source_path")
    compile_command.add_argument("staging")
    compile_command.add_argument("--entrypoint", required=True)
    compile_command.add_argument("--no-analyze", dest="analyze", action="store_false", default=None)
    _common(compile_command)
    compile_command.set_defaults(fn=_invoke, integration_tool="pythoc.compile")
    analyze = nested.add_parser("analyze-ir")
    analyze.add_argument("ir_path")
    analyze.add_argument("--llvm-version", required=True)
    _common(analyze)
    analyze.set_defaults(fn=_invoke, integration_tool="pythoc.analyze_ir")
    differential = nested.add_parser("differential")
    differential.add_argument("before_path")
    differential.add_argument("after_path")
    differential.add_argument("--argv", required=True, help="harness argv JSON array, or @file")
    differential.add_argument("--files", help="declared auxiliary files JSON object, or @file")
    differential.add_argument("--target-name")
    _common(differential)
    differential.set_defaults(fn=_invoke, integration_tool="pythoc.differential")
