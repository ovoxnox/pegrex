"""CFG fixed-point, interprocedural taint, context sinks, and secret flows.

The analysis is deliberately over-approximate. Symbolic parameter origins are
instantiated at call sites, sanitization is path-sensitive, recursive summary
cycles are widened, and an unfixed iteration is reported as UNKNOWN coverage.
"""
from __future__ import annotations

import ast
import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .schema import finding_document
from .ssa import build_function_ssa

SCHEMA = "pegrex.interprocedural-taint.v1"
SUMMARY_SCHEMA = "pegrex.taint-summary.v1"


@dataclass(frozen=True)
class SourceRule:
    id: str
    pattern: str
    kind: str = "call"  # call | name | environment
    category: str = "taint"
    pack: str = "core"


@dataclass(frozen=True)
class SinkRule:
    id: str
    pattern: str
    category: str = "injection"
    severity: str = "HIGH"
    message: str = "sensitive value reaches a sink"
    arguments: tuple[int, ...] = (0,)
    sanitizers: tuple[str, ...] = ()
    safe_keywords: tuple[tuple[str, object], ...] = ()
    safe_contexts: tuple[str, ...] = ()
    safe_state_arguments: tuple[tuple[int, tuple[object, ...]], ...] = ()
    pack: str = "core"


@dataclass(frozen=True)
class Value:
    origins: tuple[tuple, ...] = ()
    sanitized: tuple[str, ...] = ()
    unknown: bool = False

    def to_dict(self) -> dict:
        """Implement to dict with the module's explicit API and failure semantics."""
        return {"origins": [dict(zip(("kind", "name", "category", "location"), origin))
                            for origin in self.origins],
                "sanitized": list(self.sanitized), "unknown": self.unknown}


EMPTY = Value()


def _origin(kind, name, category, location) -> tuple:
    return (kind, name, category, location)


def _combine(values) -> Value:
    values = list(values)
    sanitized = set(values[0].sanitized) if values else set()
    for value in values[1:]:
        sanitized.intersection_update(value.sanitized)
    return Value(tuple(sorted({origin for value in values for origin in value.origins})),
                 tuple(sorted(sanitized)), any(value.unknown for value in values))


def _sanitize(value: Value, sanitizer: str) -> Value:
    return Value(value.origins, tuple(sorted(set(value.sanitized) | {sanitizer})),
                 value.unknown)


def _instantiate(value: Value, arguments: list[Value]) -> Value:
    origins = set()
    sanitized = set(value.sanitized)
    for kind, name, category, location in value.origins:
        if kind == "param":
            index = int(name)
            if index < len(arguments):
                argument = arguments[index]
                origins.update(argument.origins)
                sanitized.intersection_update(argument.sanitized) if argument.origins else None
            # Missing actual arguments stay symbolic and cannot be promoted to
            # a source-level finding.
            else:
                origins.add((kind, name, category, location))
        else:
            origins.add((kind, name, category, location))
    return Value(tuple(sorted(origins)), tuple(sorted(sanitized)), value.unknown)


@dataclass
class State:
    values: dict[str, Value] = field(default_factory=dict)
    guards: dict[tuple[str, str], bool] = field(default_factory=dict)

    def copy(self) -> "State":
        """Implement copy with the module's explicit API and failure semantics."""
        return State(dict(self.values), dict(self.guards))


def _join(states: list[State]) -> State:
    if not states:
        return State()
    result = states[0].copy()
    for other in states[1:]:
        for name in set(result.values) | set(other.values):
            result.values[name] = _combine([result.values.get(name, EMPTY),
                                            other.values.get(name, EMPTY)])
        result.guards = {key: value for key, value in result.guards.items()
                         if other.guards.get(key) == value}
    return result


@dataclass
class Instruction:
    id: int
    statement: ast.stmt
    successors: list[tuple[int, bool | None]] = field(default_factory=list)
    contexts: tuple[str, ...] = ()


# Pending-exit compilation keeps branch and back edges inspectable.
class FunctionCFG:
    def __init__(self, function) -> None:
        self.function = function
        self.nodes: list[Instruction] = []
        self.contexts: tuple[str, ...] = ()
        entry, exits = self.compile(function.body)
        self.entry = entry if entry is not None else self.new(ast.Pass()).id
        self.exit = self.new(ast.Pass()).id
        for source, branch in exits:
            self.nodes[source].successors.append((self.exit, branch))
        for node in self.nodes:
            node.successors = [(self.exit if target == -1 else target, branch)
                               for target, branch in node.successors]

    def new(self, statement):
        """Implement new with the module's explicit API and failure semantics."""
        row = Instruction(len(self.nodes), statement, contexts=self.contexts)
        self.nodes.append(row)
        return row

    @staticmethod
    def dotted(node):
        """Implement dotted with the module's explicit API and failure semantics."""
        if isinstance(node, ast.Call):
            return FunctionCFG.dotted(node.func)
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    def compile(self, statements):
        """Implement compile with the module's explicit API and failure semantics."""
        first, pending = None, []
        for statement in statements:
            if isinstance(statement, ast.If):
                row = self.new(statement)
                if first is None:
                    first = row.id
                for source, branch in pending:
                    self.nodes[source].successors.append((row.id, branch))
                pending = []
                body_first, body_exits = self.compile(statement.body)
                else_first, else_exits = self.compile(statement.orelse)
                if body_first is not None:
                    row.successors.append((body_first, True))
                if else_first is not None:
                    row.successors.append((else_first, False))
                pending = body_exits + else_exits
                if body_first is None:
                    pending.append((row.id, True))
                if else_first is None:
                    pending.append((row.id, False))
            elif isinstance(statement, (ast.While, ast.For)):
                row = self.new(statement)
                if first is None:
                    first = row.id
                for source, branch in pending:
                    self.nodes[source].successors.append((row.id, branch))
                pending = []
                body_first, body_exits = self.compile(statement.body)
                if body_first is not None:
                    row.successors.append((body_first, True))
                for source, branch in body_exits:
                    self.nodes[source].successors.append((row.id, branch))
                pending = [(row.id, False)]
            elif isinstance(statement, ast.With):
                previous = self.contexts
                self.contexts += tuple(self.dotted(item.context_expr) for item in statement.items)
                nested_first, nested_exits = self.compile(statement.body)
                self.contexts = previous
                if first is None:
                    first = nested_first
                for source, branch in pending:
                    self.nodes[source].successors.append((nested_first, branch))
                pending = nested_exits
            else:
                row = self.new(statement)
                if first is None:
                    first = row.id
                for source, branch in pending:
                    self.nodes[source].successors.append((row.id, branch))
                pending = [] if isinstance(statement, ast.Return) else [(row.id, None)]
        return first, pending


@dataclass
class FunctionInfo:
    module: str
    path: str
    node: ast.AST
    imports: dict[str, str]
    source: str = ""

    @property
    def key(self):
        """Implement key with the module's explicit API and failure semantics."""
        return f"{self.module}.{self.node.name}"


class FlowAnalysis:
    def __init__(self, infos, source_rules, sink_rules, *, max_rounds=8,
                 max_iterations=10_000, report_parameters=False) -> None:
        self.infos = infos
        self.source_rules = source_rules
        self.sink_rules = sink_rules
        self.max_rounds = max_rounds
        self.max_iterations = max_iterations
        self.report_parameters = report_parameters
        self.summaries = {}
        self.calls = {key: set() for key in infos}
        self.unknowns = []
        self._events = []

    def resolve(self, info: FunctionInfo, name: str):
        """Implement resolve with the module's explicit API and failure semantics."""
        if name in info.imports:
            return info.imports[name]
        local = f"{info.module}.{name}"
        if local in self.infos:
            return local
        if name in self.infos:
            return name
        first, _, remainder = name.partition(".")
        if first in info.imports:
            base = info.imports[first]
            candidate = f"{base}.{remainder}" if remainder else base
            if candidate in self.infos:
                return candidate
        return None

    def source(self, node, info, state):
        """Implement source with the module's explicit API and failure semantics."""
        if isinstance(node, ast.Name):
            if node.id in state.values:
                return state.values[node.id]
            for rule in self.source_rules:
                if rule.kind == "name" and re.fullmatch(rule.pattern, node.id, re.IGNORECASE):
                    return Value((_origin("source", node.id, rule.category,
                                          f"{info.path}:{node.lineno}"),))
            return EMPTY
        if isinstance(node, ast.Subscript) and self.dotted(node.value) in {"os.environ", "environ"}:
            for rule in self.source_rules:
                if rule.kind == "environment":
                    return Value((_origin("source", "environment", rule.category,
                                          f"{info.path}:{node.lineno}"),))
        if isinstance(node, ast.Call):
            name = self.dotted(node.func)
            arguments = [self.value(arg, info, state) for arg in node.args]
            arguments += [self.value(keyword.value, info, state) for keyword in node.keywords]
            for rule in self.source_rules:
                if rule.kind == "call" and re.fullmatch(rule.pattern, name):
                    return Value((_origin("source", name, rule.category,
                                          f"{info.path}:{node.lineno}"),))
            for rule in self.sink_rules:
                for sanitizer in rule.sanitizers:
                    if re.fullmatch(sanitizer, name) and arguments:
                        return _sanitize(arguments[0], sanitizer)
            callee = self.resolve(info, name)
            if callee and callee in self.summaries:
                returns = self.summaries[callee]["returns"]
                return _combine([_instantiate(self.from_dict(row), arguments)
                                 for row in returns]) if returns else EMPTY
            # Unknown/external calls propagate argument sensitivity but do not
            # invent a sanitization or a new source.
            return _combine(arguments)
        if isinstance(node, ast.Attribute):
            return self.value(node.value, info, state)
        if isinstance(node, ast.Subscript):
            return _combine([self.value(node.value, info, state), self.value(node.slice, info, state)])
        if isinstance(node, ast.Constant):
            return EMPTY
        if isinstance(node, ast.Compare):
            return EMPTY
        children = list(ast.iter_child_nodes(node))
        return _combine([self.value(child, info, state) for child in children]) if children else EMPTY

    def value(self, node, info, state):
        """Implement value with the module's explicit API and failure semantics."""
        return self.source(node, info, state)

    @staticmethod
    def dotted(node):
        """Implement dotted with the module's explicit API and failure semantics."""
        return FunctionCFG.dotted(node)

    def from_dict(self, row):
        """Implement from dict with the module's explicit API and failure semantics."""
        return Value(tuple((item["kind"], item["name"], item["category"], item["location"])
                           for item in row["origins"]),
                     tuple(row["sanitized"]), row["unknown"])

    def assignment(self, statement, info, state):
        """Implement assignment with the module's explicit API and failure semantics."""
        if isinstance(statement, (ast.Assign, ast.AnnAssign)):
            targets = statement.targets if isinstance(statement, ast.Assign) else [statement.target]
            if len(targets) == 1 and isinstance(targets[0], ast.Name):
                target = targets[0].id
                value = self.value(statement.value, info, state)
                if not value.origins:
                    for rule in self.source_rules:
                        if rule.kind == "name" and re.fullmatch(rule.pattern, target, re.IGNORECASE):
                            value = Value((_origin("source", target, rule.category,
                                                   f"{info.path}:{statement.lineno}"),))
                state.values[target] = value
            else:
                self.unknowns.append(f"{info.path}:{statement.lineno}: unsupported assignment target")
        elif isinstance(statement, ast.AugAssign) and isinstance(statement.target, ast.Name):
            state.values[statement.target.id] = _combine([
                state.values.get(statement.target.id, EMPTY), self.value(statement.value, info, state)])

    def guard(self, test, info, state, branch):
        """Implement guard with the module's explicit API and failure semantics."""
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.guard(test.operand, info, state, not branch)
        if isinstance(test, ast.Call) and isinstance(test.func, ast.Name) and test.args:
            name = self.dotted(test.func)
            for rule in self.sink_rules:
                for sanitizer in rule.sanitizers:
                    if re.fullmatch(sanitizer, name) and isinstance(test.args[0], ast.Name):
                        state.guards[(test.args[0].id, sanitizer)] = branch
        return state

    def sink_event(self, call, rule, info, state, contexts):
        """Implement sink event with the module's explicit API and failure semantics."""
        name = self.dotted(call.func)
        keywords = {keyword.arg: keyword.value for keyword in call.keywords if keyword.arg}
        for keyword, safe in rule.safe_keywords:
            if keyword in keywords and isinstance(keywords[keyword], ast.Constant) \
                    and keywords[keyword].value == safe:
                return None
        if any(re.fullmatch(context, manager) for context in rule.safe_contexts
               for manager in contexts):
            return None
        for index, states in rule.safe_state_arguments:
            argument = call.args[index] if index < len(call.args) else None
            if isinstance(argument, ast.Constant) and argument.value in states:
                return None
        events = []
        for index in rule.arguments:
            if index >= len(call.args):
                continue
            argument = call.args[index]
            value = self.value(argument, info, state)
            if not value.origins and not value.unknown:
                continue
            sanitized = set(value.sanitized)
            if isinstance(argument, ast.Name):
                for sanitizer in rule.sanitizers:
                    if state.guards.get((argument.id, sanitizer)) is True:
                        sanitized.add(sanitizer)
            if any(sanitizer in sanitized for sanitizer in rule.sanitizers):
                continue
            source_path = [{"kind": "source", "name": origin[1], "category": origin[2],
                            "location": origin[3]} for origin in value.origins
                           if origin[0] == "source"]
            source_path.append({"kind": "sink", "name": name, "argument": index,
                                "location": f"{info.path}:{call.lineno}"})
            events.append({"rule_id": rule.id, "category": rule.category,
                           "rule": {"id": rule.id, "pattern": rule.pattern,
                                    "pack": rule.pack, "sanitizers": list(rule.sanitizers)},
                           "severity": rule.severity, "message": rule.message,
                           "sink": name, "argument": index, "value": value.to_dict(),
                           "file": info.path, "line": call.lineno,
                           "matched_ast": {"node_type": type(call).__name__,
                               "dump": ast.dump(call, include_attributes=True),
                               "source": ast.get_source_segment(info.source, call),
                               "line": call.lineno, "column": call.col_offset,
                               "end_line": getattr(call, "end_lineno", None),
                               "end_column": getattr(call, "end_col_offset", None)},
                           "flow_path": source_path, "path_kind": "origin-callsite-sink",
                           "evidence_strength": "possible-flow" if value.unknown else "static-source-to-sink",
                           "contexts": list(contexts),
                           "kind": "unknown" if value.unknown else "taint"})
        return events

    def calls_in(self, node):
        # Composite statements are branch nodes; their nested bodies have their
        # own CFG nodes and must not be analyzed under the pre-branch state.
        """Implement calls in with the module's explicit API and failure semantics."""
        if isinstance(node, (ast.If, ast.While, ast.For)):
            node = node.test if isinstance(node, ast.If) else (
                node.test if isinstance(node, ast.While) else node.iter)
        return [row for row in ast.walk(node) if isinstance(row, ast.Call)]

    def node_events(self, instruction, info, state):
        """Implement node events with the module's explicit API and failure semantics."""
        events = []
        for call in self.calls_in(instruction.statement):
            name = self.dotted(call.func)
            for rule in self.sink_rules:
                if re.fullmatch(rule.pattern, name):
                    events.extend(self.sink_event(call, rule, info, state,
                                                  instruction.contexts) or [])
            callee = self.resolve(info, name)
            if callee and callee in self.summaries:
                arguments = [self.value(arg, info, state) for arg in call.args]
                for event in self.summaries[callee]["events"]:
                    value = _instantiate(self.from_dict(event["value"]), arguments)
                    inherited = dict(event, value=value.to_dict(), file=info.path,
                                     line=call.lineno, callsite=callee,
                                     contexts=list(instruction.contexts))
                    inherited["kind"] = "unknown" if value.unknown else "taint"
                    events.append(inherited)
        return events

    def analyze_function(self, info: FunctionInfo):
        """Implement analyze function with the module's explicit API and failure semantics."""
        cfg = FunctionCFG(info.node)
        predecessors = {node.id: [] for node in cfg.nodes}
        for node in cfg.nodes:
            for target, branch in node.successors:
                predecessors[target].append((node.id, branch))
        parameters = list(getattr(info.node.args, "posonlyargs", [])) + info.node.args.args + info.node.args.kwonlyargs
        initial = State({parameter.arg: Value((_origin("param", str(index), "parameter",
                                                       f"{info.path}:{info.node.lineno}"),))
                         for index, parameter in enumerate(parameters)})
        incoming = {cfg.entry: initial}
        outgoing = {}
        edge_outgoing = {}
        queue = [cfg.entry]
        iterations = 0
        stable = True
        while queue:
            iterations += 1
            if iterations > self.max_iterations:
                stable = False
                self.unknowns.append(f"{info.key}: CFG fixed point exceeded {self.max_iterations} iterations")
                break
            node_id = queue.pop(0)
            if node_id != cfg.entry:
                states = [edge_outgoing[(source, branch)]
                          for source, branch in predecessors[node_id]
                          if (source, branch) in edge_outgoing]
                if not states:
                    continue
                merged = _join(states)
                incoming[node_id] = merged
            node = cfg.nodes[node_id]
            state = incoming[node_id].copy()
            self.assignment(node.statement, info, state)
            if outgoing.get(node_id) == state:
                continue
            outgoing[node_id] = state
            for target, branch in node.successors:
                edge_state = state.copy()
                if branch is not None:
                    edge_state = self.guard(node.statement.test, info, edge_state, branch)
                previous = incoming.get(target)
                joined = _join([previous, edge_state]) if previous else edge_state
                edge_outgoing[(node_id, branch)] = edge_state
                if previous != joined:
                    incoming[target] = joined
                    queue.append(target)
        returns = []
        for node in cfg.nodes:
            if isinstance(node.statement, ast.Return):
                value = self.value(node.statement.value, info, incoming.get(node.id, State()))
                if value.to_dict() not in returns:
                    returns.append(value.to_dict())
        events = []
        for node in cfg.nodes:
            if node.id in incoming:
                events.extend(self.node_events(node, info, incoming[node.id]))
        unique = {}
        for event in events:
            identity = json.dumps(event, sort_keys=True, default=str)
            unique[identity] = event
        events = list(unique.values())
        ssa = build_function_ssa(info.node)
        identity = hashlib.sha256(json.dumps({"returns": returns, "events": events},
                                            sort_keys=True).encode()).hexdigest()
        return {"schema": SUMMARY_SCHEMA, "function": info.key,
                "parameters": [parameter.arg for parameter in parameters],
                "returns": returns, "events": events, "ssa": ssa,
                "fixed_point": {"stable": stable, "iterations": iterations},
                "summary_identity": identity, "unknowns": list(ssa["unknowns"])}

    @staticmethod
    def merge_summary(old, new):
        """Implement merge summary with the module's explicit API and failure semantics."""
        if old is None:
            return new
        returns = []
        for row in old["returns"] + new["returns"]:
            if row not in returns:
                returns.append(row)
        events = {json.dumps(row, sort_keys=True): row
                  for row in old["events"] + new["events"]}
        result = dict(new, returns=returns, events=list(events.values()))
        result["summary_identity"] = hashlib.sha256(json.dumps(
            {"returns": returns, "events": result["events"]}, sort_keys=True).encode()).hexdigest()
        return result

    def run(self):
        """Implement run with the module's explicit API and failure semantics."""
        previous = {}
        stable = False
        rounds = 0
        for rounds in range(1, self.max_rounds + 1):
            current = {}
            for key, info in self.infos.items():
                current[key] = self.merge_summary(previous.get(key), self.analyze_function(info))
            for info in self.infos.values():
                for call in self.calls_in(info.node):
                    resolved = self.resolve(info, self.dotted(call.func))
                    if resolved:
                        self.calls[info.key].add(resolved)
            if {key: value["summary_identity"] for key, value in current.items()} == \
                    {key: value["summary_identity"] for key, value in previous.items()}:
                stable = True
                self.summaries = current
                break
            previous = current
            self.summaries = current
        if not stable:
            self.unknowns.append(f"interprocedural summaries did not converge in {self.max_rounds} rounds")
        recursive = {key for key, callees in self.calls.items()
                     if self._reaches(key, key, set(), skip_start=True)}
        for key in recursive:
            self.summaries[key]["recursion_widened"] = True
            self.summaries[key]["unknowns"].append(
                "recursive summary reached a widened over-approximation")
        findings = []
        for summary in self.summaries.values():
            for event in summary["events"]:
                value = self.from_dict(event["value"])
                if any(origin[0] == "source" for origin in value.origins) or \
                        (self.report_parameters and any(origin[0] == "param" for origin in value.origins)):
                    findings.append(self.public_finding(event))
        unique = {json.dumps(row, sort_keys=True): row for row in findings}
        return {"schema": SCHEMA, "fixed_point": {
                    "stable": stable, "rounds": rounds,
                    "widened": sorted(recursive), "max_rounds": self.max_rounds},
                "summaries": self.summaries,
                "findings": [unique[key] for key in sorted(unique)],
                "unknowns": sorted(set(self.unknowns))}

    def _reaches(self, start, target, seen, skip_start=False):
        for callee in self.calls.get(start, ()):
            if callee == target and (not skip_start or start != target):
                return True
            if callee == target and start == target:
                return True
            if callee not in seen and self._reaches(callee, target, seen | {callee}):
                return True
        return False

    @staticmethod
    def public_finding(event):
        """Implement public finding with the module's explicit API and failure semantics."""
        value = event["value"]
        sources = []
        for origin in value["origins"]:
            if origin["kind"] != "source":
                continue
            file, separator, line = origin["location"].rpartition(":")
            sources.append({**origin, "file": file if separator else event["file"],
                            "line": int(line) if separator and line.isdigit() else 1,
                            "evidence": origin["name"]})
        return finding_document({"id": event["rule_id"], "severity": event["severity"],
            "confidence": "medium", "line": event["line"], "evidence": event["sink"],
            "message": event["message"], "kind": event["kind"], "file": event["file"],
            "category": event["category"], "sink": event["sink"], "sources": sources,
            "rule": event.get("rule"), "matched_ast": event.get("matched_ast"),
            "flow_path": event.get("flow_path", sources + [{"kind": "sink", "name": event["sink"],
                                  "location": f"{event['file']}:{event['line']}"}]),
            "path_kind": event.get("path_kind", "origin-callsite-sink"),
            "evidence_strength": event.get("evidence_strength",
                                            "possible-flow" if event["kind"] == "unknown" else "static-source-to-sink"),
            "callsite": event.get("callsite"),
            "sanitized": value["sanitized"], "contexts": event.get("contexts", []),
            "suppressed": False})


def _module_infos(sources: dict[str, tuple[str, str]]):
    infos = {}
    for module, (path, source) in sorted(sources.items()):
        tree = ast.parse(source, filename=path)
        imports = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                for alias in node.names:
                    imports[alias.asname or alias.name] = f"{node.module}.{alias.name}"
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    imports[alias.asname or alias.name.split(".")[0]] = alias.name
        module_body = []
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                info = FunctionInfo(module, path, node, imports, source)
                infos[info.key] = info
            elif not isinstance(node, ast.ClassDef):
                module_body.append(node)
        if module_body:
            root = ast.FunctionDef(name="$module", args=ast.arguments(
                posonlyargs=[], args=[], kwonlyargs=[], kw_defaults=[], defaults=[]),
                body=module_body, decorator_list=[])
            root = ast.fix_missing_locations(root)
            info = FunctionInfo(module, path, root, imports, source)
            infos[info.key] = info
    return infos


def analyze_modules(sources: dict[str, tuple[str, str]], *, source_rules=(), sink_rules=(),
                    max_rounds=8, report_parameters=False) -> dict:
    """Implement analyze modules with the module's explicit API and failure semantics."""
    analysis = FlowAnalysis(_module_infos(sources), source_rules or DEFAULT_SOURCES,
                            sink_rules or DEFAULT_SINKS, max_rounds=max_rounds,
                            report_parameters=report_parameters)
    return analysis.run()


def analyze_source(source: str, *, path="<memory>.py", module="memory", source_rules=(),
                   sink_rules=(), report_parameters=True) -> dict:
    """Implement analyze source with the module's explicit API and failure semantics."""
    return analyze_modules({module: (path, source)}, source_rules=source_rules,
                           sink_rules=sink_rules, report_parameters=report_parameters)


def analyze_repository(root: str | Path, *, secret=False, report_parameters=False) -> dict:
    """Implement analyze repository with the module's explicit API and failure semantics."""
    root = Path(root)
    sources = {}
    for path in sorted(root.rglob("*.py")):
        if any(part in {"__pycache__", ".venv", "venv", ".git"} for part in path.parts):
            continue
        relative = path.relative_to(root)
        module = ".".join(relative.with_suffix("").parts)
        if module.endswith(".__init__"):
            module = module.removesuffix(".__init__")
        sources[module] = (str(path), path.read_text(encoding="utf-8"))
    return analyze_modules(sources, source_rules=SECRET_SOURCES if secret else DEFAULT_SOURCES,
                           sink_rules=SECRET_SINKS if secret else DEFAULT_SINKS,
                           report_parameters=report_parameters)


DEFAULT_SOURCES = (
    SourceRule("python-input", r"(?:builtins\.)?input", category="user-input"),
    SourceRule("request", r"(?:request|req)(?:\..*)?", kind="name", category="user-input"),
)
DEFAULT_SINKS = (
    SinkRule("code-injection", r"(?:builtins\.)?(?:eval|exec|compile)",
             category="code-injection", sanitizers=(r"(?:ast\.)?literal_eval", r"sanitize")),
    SinkRule("command-injection", r"(?:os\.)?system", category="command-injection",
             sanitizers=(r"shlex\.quote",)),
)
SECRET_SOURCES = (
    SourceRule("secret-name", r".*(?:password|passwd|secret|token|api[_-]?key|credential).*",
               kind="name", category="secret"),
    SourceRule("secret-environment", r".*", kind="environment", category="secret"),
    SourceRule("secret-read", r"(?:getpass\.)?getpass|read_(?:password|secret|token)",
               category="secret"),
    SourceRule("secret-config", r"(?:os\.)?getenv|(?:os\.)?environ\.get|.*(?:config|configuration)\.(?:get|read).*",
               category="configuration-secret"),
)
SECRET_SINKS = (
    SinkRule("secret-log", r"(?:print|logging\..*|logger\..*|log\..*)",
             category="log", message="secret reaches a log sink", sanitizers=(r"redact|mask_secret",)),
    SinkRule("secret-telemetry", r".*(?:telemetry|analytics|sentry)\..*|.*(?:track|capture)_(?:event|error)",
             category="telemetry", message="secret reaches telemetry", sanitizers=(r"redact|mask_secret",)),
    SinkRule("secret-url", r"(?:requests|httpx)\.(?:get|post|put|patch|delete|request)",
             category="url", message="secret reaches a request URL or payload", arguments=(0, 1, 2),
              sanitizers=(r"redact|mask_secret",)),
    SinkRule("secret-process", r"(?:os\.)?system|subprocess\.(?:run|Popen|call|check_output)",
             category="process-arguments", message="secret reaches process arguments",
             sanitizers=(r"redact|mask_secret",)),
    SinkRule("secret-network", r".*(?:socket|connection)\..*(?:send|write)|(?:requests|httpx)\..*",
             category="network", message="secret reaches a network sink", arguments=(0, 1, 2),
              sanitizers=(r"redact|mask_secret",)),
)


def analyze_secrets(source: str, *, path="<memory>.py") -> dict:
    """Implement analyze secrets with the module's explicit API and failure semantics."""
    return analyze_source(source, path=path, source_rules=SECRET_SOURCES,
                          sink_rules=SECRET_SINKS, report_parameters=False)
