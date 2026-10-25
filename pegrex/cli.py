"""
pegrex CLI

The complete command-line interface (argparse subcommands).
Every engine capability, one entry point: `pegrex <command> -h`"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

from .commands.common import ROOT, _emit_json, _expand

__version__ = "1.0.0"
sys.path.insert(0, str(ROOT))
from .commands.analysis import (
    _cmd_audit,
    _cmd_spec,
    _cmd_contracts,
    _cmd_callgraph,
    _cmd_coverage,
    _cmd_gaps,
    _cmd_tests,
    _cmd_budget,
    _cmd_index,
    _cmd_bundle,
    _cmd_health,
    _cmd_probpath,
    _cmd_cognitive,
    _cmd_audit_bounded,
    _cmd_probverify,
    _cmd_difforacle,
)
from .commands.verification import (
    _cmd_verify,
    _cmd_certs,
    _cmd_soundness,
    _cmd_verify_patch,
    _cmd_diff,
    _cmd_emit,
    _cmd_check,
    _cmd_mine,
    _cmd_concolic,
    _cmd_strategy,
    _cmd_modernize,
    _cmd_tv,
    _cmd_zk,
    _cmd_harness_check,
    _cmd_mlcheck,
    _cmd_twin,
    _cmd_attest,
    _cmd_vapi,
    _cmd_roundtrip,
    _cmd_legal_ci,
    _cmd_ic3,
    _cmd_insure,
)
from .commands.tooling import (
    _cmd_lint,
    _cmd_extract,
    _cmd_rules,
    _cmd_serve,
    _cmd_acp,
    _cmd_mcp,
    _cmd_induce,
    _cmd_workrun,
    _cmd_metaengine,
    _cmd_ci,
    _cmd_osv,
    _cmd_explain,
    _cmd_caps,
    _cmd_export,
    _cmd_nl,
    _cmd_rank,
    _cmd_bench,
    _cmd_compress,
    _cmd_iac,
    _cmd_bounty,
    _cmd_compliance,
    _cmd_compile_nl,
    _cmd_autopwn,
    _cmd_orgtwin,
    _cmd_selfhost,
    _cmd_rosetta,
    _cmd_llmcegis,
    _cmd_golf,
)

def _cmd_dispatch(mod, fn):
    def h(args):
        m = __import__("pegrex." + mod, fromlist=[fn])
        import inspect as _i
        f = getattr(m, fn)
        sig = _i.signature(f)
        kwargs = {}
        for p in sig.parameters.values():
            if p.name == "src" and hasattr(args, "file"):
                kwargs["src"] = open(args.file).read()
            elif hasattr(args, p.name):
                kwargs[p.name] = getattr(args, p.name)
        _emit_json(f(**kwargs))
    return h

def build_parser() -> argparse.ArgumentParser:
    """build parser(): see module docstring."""
    p = argparse.ArgumentParser(
        prog="pegrex",
        description="Self-contained symbolic-execution and syntactic-analysis "
                    "engine: source -> mathematical specifications for AI agents.",
        epilog="certificates: `pegrex certs` runs all 67 proofs. "
               "Each command accepts -h.")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", metavar="<command>")
    sp = sub.add_parser("audit", help="security audit (patterns + taint + SCA)")
    sp.add_argument("file", nargs="?")
    sp.add_argument("--dir", nargs="?", const=True, default=False,
                    metavar="PATH", help="recurse a directory (parallel)")
    sp.add_argument("--lang")
    audit_output = sp.add_mutually_exclusive_group()
    audit_output.add_argument("--json", action="store_true")
    audit_output.add_argument("--sarif", action="store_true",
                              help="emit SARIF 2.1.0 for GitHub Code Scanning")
    sp.add_argument("--out", help="also write the selected audit report")
    sp.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"],
                    help="exit 1 when a non-unknown finding meets this severity")
    sp.add_argument("--fail-on-unknown", action="store_true",
                    help="exit 2 when scanner coverage is incomplete")
    sp.set_defaults(fn=_cmd_audit)
    sp = sub.add_parser("spec", help="AI spec schema (multi-view)")
    sp.add_argument("source", nargs="?")
    sp.add_argument("--dir", nargs="?", const=True, default=False,
                    metavar="PATH", help="recurse a directory")
    sp.add_argument("name")
    sp.add_argument("--out", default="specs")
    sp.add_argument("--opus", help="comma list of perspectives")
    sp.add_argument("--analyzers", help="comma list of analyzers")
    sp.set_defaults(fn=_cmd_spec)
    sp = sub.add_parser("contracts", help="function contract (paths -> results)")
    sp.add_argument("file")
    sp.add_argument("--lang", default="python")
    sp.set_defaults(fn=_cmd_contracts)
    sp = sub.add_parser("callgraph", help="function-call graph (DOT/ASCII)")
    sp.add_argument("file", nargs="?")
    sp.add_argument("--dir", nargs="?", const=True, default=False,
                    metavar="PATH",
                    help="recurse a directory (positional or this path)")
    sp.add_argument("--lang", default="python")
    sp.add_argument("--ascii", action="store_true")
    sp.add_argument("--jobs", type=int, default=1,
                    help="opt into spawn-based process workers for --dir")
    sp.add_argument("--benchmark", action="store_true",
                    help="measure sequential/process overhead for --dir")
    sp.set_defaults(fn=_cmd_callgraph)
    sp = sub.add_parser("coverage", help="path coverage overlay + gaps")
    sp.add_argument("source", nargs="?")
    sp.add_argument("--dir", nargs="?", const=True, default=False,
                    metavar="PATH", help="recurse a directory")
    sp.add_argument("--lcov", required=True)
    sp.add_argument("--lang", default="python")
    sp.set_defaults(fn=_cmd_coverage)
    sp = sub.add_parser("gaps", help="coverage gaps with constraint context")
    sp.add_argument("source")
    sp.add_argument("--lcov", required=True)
    sp.add_argument("--lang", default="python")
    sp.set_defaults(fn=_cmd_gaps)
    sp = sub.add_parser("tests", help="synthesize tests from coverage gaps")
    sp.add_argument("source")
    sp.add_argument("--lcov", required=True)
    sp.set_defaults(fn=_cmd_tests)
    sp = sub.add_parser("budget", help="complexity budget gate (exit 1 on fail)")
    sp.add_argument("file", nargs="?")
    sp.add_argument("--dir", nargs="?", const=True, default=False,
                    metavar="PATH", help="recurse a directory")
    sp.add_argument("--max-loc", type=int, default=300)
    sp.add_argument("--max-function-lines", type=int, default=40)
    sp.set_defaults(fn=_cmd_budget)
    sp = sub.add_parser("index", help="repo arch index")
    sp.add_argument("dir")
    sp.add_argument("--out", default="repo.index.json")
    sp.set_defaults(fn=_cmd_index)
    sp = sub.add_parser("bundle", help="portable verification bundle")
    sp.add_argument("source", nargs="?")
    sp.add_argument("--dir", nargs="?", const=True, default=False,
                    metavar="PATH", help="recurse a directory")
    sp.add_argument("--out")
    sp.set_defaults(fn=_cmd_bundle)
    sp = sub.add_parser("soundness", help="canonical frontend plugins and trust policy")
    sp.add_argument("--language", help="restrict the report to one registered language")
    sp.set_defaults(fn=_cmd_soundness)
    sp = sub.add_parser("rules", help="rule catalog summary")
    sp.add_argument("--json", action="store_true")
    sp.add_argument("--lang", default=None, help="report language-specific coverage")
    sp.set_defaults(fn=_cmd_rules)
    sp = sub.add_parser("lint", help="grammar lint")
    sp.add_argument("grammars", nargs="+")
    sp.set_defaults(fn=_cmd_lint)
    sp = sub.add_parser("extract", help="verbatim grammar extraction")
    sp.add_argument("upstream")
    sp.add_argument("out")
    sp.set_defaults(fn=_cmd_extract)
    sp = sub.add_parser("induce", help="grammar induction (examples -> grammar)")
    sp.add_argument("positives", help="file of positive example lines")
    sp.add_argument("--negatives", help="file of negative example lines")
    sp.add_argument("--seed", help="seed grammar file")
    sp.add_argument("--out", help="write induced grammar here")
    sp.add_argument("--rounds", type=int, default=60)
    sp.set_defaults(fn=_cmd_induce)
    sp = sub.add_parser("workrun", help="execute a .work agent")
    sp.add_argument("work")
    sp.add_argument("--target", help="source file the agent analyzes")
    sp.set_defaults(fn=_cmd_workrun)
    sp = sub.add_parser("metaengine",
                        help="examples -> grammar -> tags -> rule skeletons")
    sp.add_argument("positives")
    sp.add_argument("--negatives")
    sp.add_argument("--domain", default="custom")
    sp.add_argument("--out")
    sp.set_defaults(fn=_cmd_metaengine)
    sp = sub.add_parser("health", help="self code-health spec")
    sp.add_argument("path")
    sp.set_defaults(fn=_cmd_health)
    sp = sub.add_parser("verify", help="translation certificate")
    sp.add_argument("spec")
    sp.set_defaults(fn=_cmd_verify)
    sp = sub.add_parser("cisec", help="CI/CD pipeline security analysis")
    sp.add_argument("file")
    sp.set_defaults(fn=_cmd_ci)
    sp = sub.add_parser("osvscan", help="dependency vulnerability scan (OSV)")
    sp.add_argument("file")
    sp.add_argument("--offline", action="store_true",
                    help="disable network; missing cache entries become UNKNOWN")
    sp.add_argument("--osv-snapshot", help="reproducible local OSV query snapshot")
    sp.add_argument("--snapshot-out", help="capture complete query results for offline reuse")
    sp.add_argument("--fail-on-unknown", action="store_true",
                    help="exit 2 when vulnerability coverage is incomplete")
    sp.set_defaults(fn=_cmd_osv)
    sp = sub.add_parser("export", help="export findings (json/csv/html)")
    sp.add_argument("file")
    sp.add_argument("--format", default="json",
                    choices=["json", "csv", "html", "sarif"])
    sp.add_argument("--out")
    sp.set_defaults(fn=_cmd_export)
    sp = sub.add_parser("explain", help="explain a function as math")
    sp.add_argument("file")
    sp.add_argument("--lang", default="python")
    sp.set_defaults(fn=_cmd_explain)
    sp = sub.add_parser("caps", help="infer capabilities + sandbox policy")
    sp.add_argument("file")
    sp.set_defaults(fn=_cmd_caps)
    sp = sub.add_parser("certs", help="run ALL certificates + negative control")
    sp.set_defaults(fn=_cmd_certs)
    sp = sub.add_parser("serve", help="JSON-lines service (stdio)")
    sp.set_defaults(fn=_cmd_serve)
    sp = sub.add_parser("acp", help="ACP server (Zed-compatible)")
    sp.add_argument("root", nargs="?", default=".")
    sp.set_defaults(fn=_cmd_acp)
    sp = sub.add_parser("mcp", help="MCP server (tools + resources + router)")
    sp.set_defaults(fn=_cmd_mcp)
    sp = sub.add_parser("verify-patch", help="proof or counterexample for two sources")
    sp.add_argument("before")
    sp.add_argument("after")
    sp.add_argument("--claim", default="equivalent")
    sp.set_defaults(fn=_cmd_verify_patch)
    sp = sub.add_parser("diff", help="semantic diff (path contracts, not lines)")
    sp.add_argument("a")
    sp.add_argument("b")
    sp.set_defaults(fn=_cmd_diff)
    sp = sub.add_parser("emit", help="emit executable code from the contract IR")
    sp.add_argument("file")
    sp.add_argument("--run", action="store_true", help="print raw code")
    sp.set_defaults(fn=_cmd_emit)
    sp = sub.add_parser("check", help="discharge refinement contracts (requires/ensures)")
    sp.add_argument("file")
    sp.add_argument("--requires", action="append")
    sp.add_argument("--ensures", action="append")
    sp.set_defaults(fn=_cmd_check)
    sp = sub.add_parser("mine", help="mine likely invariants from path contracts")
    sp.add_argument("file")
    sp.set_defaults(fn=_cmd_mine)
    sp = sub.add_parser("nl", help="check a natural-language claim against the contracts")
    sp.add_argument("file")
    sp.add_argument("text")
    sp.set_defaults(fn=_cmd_nl)
    sp = sub.add_parser("concolic", help="trace a run and flip a branch")
    sp.add_argument("file")
    sp.add_argument("--fn", dest="fn_name", required=True)
    sp.add_argument("--args", type=int, nargs="*", default=[])
    sp.add_argument("--flip", type=int)
    sp.set_defaults(fn=_cmd_concolic)
    sp = sub.add_parser("rank", help="find a termination ranking function")
    sp.add_argument("guard")
    sp.add_argument("--delta", action="append", default=[], metavar="VAR=INT")
    sp.set_defaults(fn=_cmd_rank)
    sp = sub.add_parser("bench", help="deterministic agent-edit benchmark")
    sp.set_defaults(fn=_cmd_bench)
    sp = sub.add_parser("compress", help="LLM context compression (contracts + findings)")
    sp.add_argument("file")
    sp.set_defaults(fn=_cmd_compress)
    sp = sub.add_parser("strategy", help="Hypothesis strategies from path constraints")
    sp.add_argument("file")
    sp.add_argument("--fn", dest="fn_name")
    sp.set_defaults(fn=_cmd_strategy)
    sp = sub.add_parser("a2a", help="serve the agent-to-agent JSON-lines endpoint")
    sp.set_defaults(fn=lambda args: __import__("pegrex.a2a", fromlist=["serve"]).serve(sys.stdin, sys.stdout))
    sp = sub.add_parser("lsp", help="serve the LSP endpoint (Content-Length framing)")
    sp.set_defaults(fn=lambda args: __import__("pegrex.lsp", fromlist=["serve"]).serve(sys.stdin, sys.stdout.buffer))
    sp = sub.add_parser("modernize", help="legacy (COBOL/Fortran) -> target with equivalence certificate")
    sp.add_argument("file")
    sp.add_argument("--target", default="python")
    sp.set_defaults(fn=_cmd_modernize)
    sp = sub.add_parser("tv", help="normalize a result JSON to three-valued verdict")
    sp.add_argument("result", nargs="?")
    sp.set_defaults(fn=_cmd_tv)
    sp = sub.add_parser("zk", help="audit a Circom circuit for under-constrained signals")
    sp.add_argument("file")
    sp.set_defaults(fn=_cmd_zk)
    sp = sub.add_parser("iac", help="IAM/Terraform policy audit (or 'ACTION on RESOURCE' via --policy)")
    sp.add_argument("file", nargs="?")
    sp.add_argument("--policy")
    sp.add_argument("--question")
    sp.set_defaults(fn=_cmd_iac)
    sp = sub.add_parser("harness-check", help="check an agent plan JSON against the safety policy")
    sp.add_argument("plan")
    sp.set_defaults(fn=_cmd_harness_check)
    sp = sub.add_parser("bounty", help="discover/solve/minimize a PoC for a sink")
    sp.add_argument("file")
    sp.add_argument("sink")
    sp.set_defaults(fn=_cmd_bounty)
    sp = sub.add_parser("compliance", help="GDPR data-flow + optional SOC2 control audit")
    sp.add_argument("file")
    sp.add_argument("--soc2")
    sp.set_defaults(fn=_cmd_compliance)
    sp = sub.add_parser("mlcheck", help="quant/prune equivalence from a JSON spec")
    sp.add_argument("spec")
    sp.set_defaults(fn=_cmd_mlcheck)
    sp = sub.add_parser("twin", help="ask the codebase twin a reachability question")
    sp.add_argument("root")
    sp.add_argument("question")
    sp.set_defaults(fn=_cmd_twin)
    sp = sub.add_parser("probpath", help="path frequencies + priorities from traces (JSON spec)")
    sp.add_argument("spec")
    sp.set_defaults(fn=_cmd_probpath)
    sp = sub.add_parser("attest", help="SLSA-style attest/verify/publish (sigstore refuses offline)")
    sp.add_argument("--builder", default="local")
    sp.add_argument("--command", default="")
    sp.add_argument("--materials", default="")
    sp.add_argument("--key", default="local-key")
    sp.add_argument("--verify")
    sp.add_argument("--publish", action="store_true")
    sp.add_argument("--token")
    sp.set_defaults(fn=_cmd_attest)
    sp = sub.add_parser("vapi", help="time-bounded verify-or-refuse with SLA tracking")
    sp.add_argument("before")
    sp.add_argument("after")
    sp.add_argument("deadline_ms", type=int)
    sp.set_defaults(fn=_cmd_vapi)
    sp = sub.add_parser("cognitive", help="cognitive complexity + refactor plans (complexipy-faithful)")
    sp.add_argument("file")
    sp.add_argument("--budget", type=int, default=7)
    sp.add_argument("--fail-on-over", action="store_true",
                    help="exit 1 when any function exceeds the budget (CI gate)")
    sp.set_defaults(fn=_cmd_cognitive)
    sp = sub.add_parser("audit-bounded", help="audit under a latency budget (unknown on overrun)")
    sp.add_argument("file")
    sp.add_argument("--timeout-ms", type=int, default=30000)
    sp.set_defaults(fn=_cmd_audit_bounded)
    sp = sub.add_parser("compile-nl", help="anti-hallucination compiler: NL -> code -> proof (or refusal)")
    sp.add_argument("text")
    sp.add_argument("file")
    sp.set_defaults(fn=_cmd_compile_nl)
    sp = sub.add_parser("autopwn", help="policy-gated discover/solve/repair loop")
    sp.add_argument("file")
    sp.add_argument("sink")
    sp.add_argument("--patch", required=True, help="proposed fix source file")
    sp.add_argument("--rounds", type=int, default=4)
    sp.set_defaults(fn=_cmd_autopwn)
    sp = sub.add_parser("probverify", help="verify under budget, hot paths first, coverage attached")
    sp.add_argument("spec", help="JSON: {file, traces, verdicts}")
    sp.add_argument("--deadline-ms", type=int, default=1000)
    sp.set_defaults(fn=_cmd_probverify)
    sp = sub.add_parser("roundtrip", help="Python -> COBOL round-trip with contract identity")
    sp.add_argument("file")
    sp.add_argument("--print-cobol", action="store_true")
    sp.set_defaults(fn=_cmd_roundtrip)
    sp = sub.add_parser("legal-ci", help="contract-deadline CI artifact")
    sp.add_argument("file")
    sp.add_argument("--warn-days", type=int, default=14)
    sp.set_defaults(fn=_cmd_legal_ci)
    sp = sub.add_parser("orgtwin", help="org report: teams x compliance x complexity")
    sp.add_argument("root")
    sp.add_argument("--budget", type=int, default=7)
    sp.set_defaults(fn=_cmd_orgtwin)
    sp = sub.add_parser("selfhost", help="regenerate (or --check) docs/SELF.md, the engine's self-audit")
    sp.add_argument("--check", action="store_true")
    sp.set_defaults(fn=_cmd_selfhost)
    sp = sub.add_parser("rosetta", help="N-way cross-language equivalence (semantic diff matrix)")
    sp.add_argument("spec", help="spec JSON: {name, variants: [{language, source} x N>=2]}")
    sp.set_defaults(fn=_cmd_rosetta)
    sp = sub.add_parser("difforacle", help="differential oracle: pegrex contracts vs cc-compiled binary")
    sp.add_argument("--seed", type=int, default=0)
    sp.add_argument("-n", type=int, default=20)
    sp.add_argument("--cc", default="cc")
    sp.add_argument("--canary", action="store_true", help="run the signed-overflow UB canary instead")
    sp.set_defaults(fn=_cmd_difforacle)
    sp = sub.add_parser("llmcegis", help="CEGIS repair: LLM/template proposers, FM rejecters")
    sp.add_argument("file", help="source to repair")
    sp.add_argument("--claim", default="equivalent")
    sp.add_argument("--proposer", default="templates", choices=["templates", "http"])
    sp.add_argument("--endpoint", help="HTTP proposer endpoint (or PEGREX_LLM_ENDPOINT)")
    sp.add_argument("--rounds", type=int, default=6)
    sp.set_defaults(fn=_cmd_llmcegis)
    sp = sub.add_parser("ic3", help="IC3-lite: prove/refute/unknown a linear safety property")
    sp.add_argument("--init", action="append", required=True)
    sp.add_argument("--trans", action="append", required=True)
    sp.add_argument("--prop", required=True)
    sp.add_argument("--frames", type=int, default=6)
    sp.set_defaults(fn=_cmd_ic3)
    sp = sub.add_parser("golf", help="performance-golf a cert fixture vs its baseline")
    sp.add_argument("cert")
    sp.add_argument("--baseline")
    sp.set_defaults(fn=_cmd_golf)
    sp = sub.add_parser("insure", help="quote/verify a Solidity overflow-risk premium")
    sp.add_argument("file")
    sp.add_argument("--key", default="local-key")
    sp.add_argument("--bits", type=int, default=256)
    sp.add_argument("--verify", action="store_true")
    sp.set_defaults(fn=_cmd_insure)
    return p
# --help catalog: one compact usage line per command


def _fmt_action(a):

    """Compact token for one argparse action: --flag <val>, <pos>, <pos>..."""

    mt = a.metavar or a.dest

    if isinstance(mt, tuple):

        mt = mt[0]

    if a.option_strings:

        flag = a.option_strings[0]

        if a.nargs == 0:

            return flag

        if a.nargs in ("*", "+"):

            return flag + " <" + str(mt) + ">..."

        if isinstance(a.nargs, int) and a.nargs > 1:

            return flag + " <" + str(mt) + ">x" + str(a.nargs)

        return flag + " <" + str(mt) + ">"

    if a.nargs in ("+", "*"):

        return "<" + str(mt) + ">..."

    if isinstance(a.nargs, int) and a.nargs > 1:

        return " ".join("<" + str(mt) + ">" for _ in range(a.nargs))

    return "<" + str(mt) + ">"

def _use_color() -> bool:

    """TTY-aware color: on for terminals unless NO_COLOR; force with

    PEGREX_COLOR=always/never."""

    import os as _os

    forced = _os.environ.get("PEGREX_COLOR", "")

    if forced.lower() == "always":

        return True

    if forced.lower() == "never" or "NO_COLOR" in _os.environ:

        return False

    try:

        return sys.stdout.isatty()

    except Exception:

        return False

_C = {"rst": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",

      "cyan": "\033[36m", "yellow": "\033[33m", "green": "\033[32m",

      "magenta": "\033[35m", "blue": "\033[34m", "rule": "\033[90m"}

def _paint(color: str, text: str, on: bool) -> str:

    return (_C[color] + text + _C["rst"]) if on else text

def _fmt_action(a):

    """Compact token for one argparse action: --flag <v>, <pos>, <pos>..."""

    mt = a.metavar or a.dest

    if isinstance(mt, tuple):

        mt = mt[0]

    if a.option_strings:

        flag = a.option_strings[0]

        if a.nargs == 0:

            return flag

        if a.nargs in ("*", "+"):

            return flag + " <" + str(mt) + ">..."

        if isinstance(a.nargs, int) and a.nargs > 1:

            return flag + " <" + str(mt) + ">x" + str(a.nargs)

        return flag + " <" + str(mt) + ">"

    if a.nargs in ("+", "*"):

        return "<" + str(mt) + ">..."

    if isinstance(a.nargs, int) and a.nargs > 1:

        return " ".join("<" + str(mt) + ">" for _ in range(a.nargs))

    return "<" + str(mt) + ">"

_SECTIONS = [

    ("Analysis & Audit", ["audit", "audit-bounded", "contracts", "callgraph",

                           "coverage", "gaps", "cognitive", "diff", "compress",

                           "twin", "orgtwin"]),

    ("Verification & Proofs", ["verify", "verify-patch", "check", "certs",

                                  "rank", "ic3", "transpile", "roundtrip",

                                  "probverify"]),

    ("Repair & Synthesis", ["repair", "mine", "nl", "compile-nl", "modernize",

                              "cegis", "autopwn", "bounty", "strategy"]),

    ("Security & Compliance", ["harness-check", "zk", "iac", "compliance",

                                 "legal-ci", "insure", "golf", "attest",

                                 "osvscan", "cisec"]),

    ("Execution & Testing", ["concolic", "bench", "probpath", "testsynth",

                               "selfhost"]),

    ("Protocol Endpoints", ["a2a", "lsp", "acp", "mcp"]),

    ("Repo Tooling", ["index", "bundle", "rules", "soundness", "lint", "extract", "induce",

                        "workrun", "metaengine", "health", "budget", "caps",

                        "explain", "export", "spec", "mlcheck", "tv"]),

]

def format_command_catalog(parser) -> str:

    """Segmented, colorful catalog: sections group related commands; each

    line is name: --flag <v> <pos>...  description, syntax-colored.

    Plain text on non-TTY (or NO_COLOR)."""

    import argparse as _ap

    on = _use_color()

    subs = next((a for a in parser._actions

                 if isinstance(a, _ap._SubParsersAction)), None)

    if subs is None:

        return parser.format_help()

    helps = {a.metavar: a.help for a in subs._choices_actions}

    def render(name: str) -> str:

        sub = subs.choices[name]

        flags, pos = [], []

        for a in sub._actions:

            if a.option_strings:

                if a.dest == "help":

                    continue

                flags.append(_paint("yellow", _fmt_action(a), on))

            else:

                pos.append(_paint("green", _fmt_action(a), on))

        parts = [_paint("bold", _paint("cyan", name + ":", on), on)]

        parts.extend(flags)

        parts.extend(pos)

        desc = (sub.description or helps.get(name) or "").strip()

        line = " ".join(parts)

        if desc:

            line += "  " + _paint("dim", desc, on)

        return line

    out = []

    out.append(_paint("bold", _paint("blue", "pegrex", on), on) + " " +

               _paint("dim", "command catalog", on))

    out.append(_paint("rule", "=" * 60, on))

    grouped, seen = [], set()

    for sec, members in _SECTIONS:

        present = [m for m in members if m in subs.choices]

        if not present:

            continue

        seen |= set(present)

        grouped.append((sec, present))

    other = [n for n in sorted(subs.choices) if n not in seen]

    if other:

        grouped.append(("Other commands", other))

    for sec, members in grouped:

        out.append("")

        head = _paint("bold", _paint("magenta", ">> " + sec, on), on)

        out.append(head + " " + _paint("dim", "(%d)" % len(members), on))

        out.append(_paint("rule", "-" * 60, on))

        out.extend("  " + render(m) for m in members)

    out.append("")

    out.append(_paint("dim", str(len(subs.choices)) + " commands - use "

                      "<command> --help for full details; "

                      "PEGREX_COLOR=always/never forces color", on))

    return chr(10).join(out)

def _emit_json(obj):

    import json as _json

    print(_json.dumps(obj, indent=1, default=str))

def main(argv=None) -> int:

    if argv is None:

        argv = sys.argv[1:]

    if any(a in ("-h", "--help") for a in argv):

        first = next((a for a in argv if not a.startswith("-")), None)

        if first is None:

            print(format_command_catalog(build_parser()))

            return 0

    parser = build_parser()

    args = parser.parse_args(argv)

    if not hasattr(args, "fn"):

        print(format_command_catalog(parser))

        return 0

    try:

        return args.fn(args)

    except KeyboardInterrupt:

        return 130

    except SystemExit as e:

        return e.code or 0

if __name__ == "__main__":

    sys.exit(main())
