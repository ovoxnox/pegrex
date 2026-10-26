"""Version-specific LLVM IR, Rust MIR, and MLIR control-flow parsers.

Edges come only from parsed terminator syntax. No regular expressions or
control-flow guesses are used in proof mode.
"""
from __future__ import annotations

import hashlib

SCHEMA = "pegrex.compiler-ir.v1"
_GRAMMARS = {("llvm", "17"): "llvm-ir-17-block-terminators-v1",
             ("llvm", "18"): "llvm-ir-18-block-terminators-v1",
             ("mir", "rust-1"): "rust-mir-rust-1-bb-terminators-v1",
             ("mlir", "1"): "mlir-1-cf-terminators-v1"}


class _IRParser:
    def __init__(self, format):
        self.format = format
        self.functions = []
        self.function = None
        self.block = None
        self.unknowns = []

    def parse(self, text):
        """Implement parse with the module's explicit API and failure semantics."""
        for number, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith(("//", "#")):
                continue
            if self.format == "llvm" and line.startswith(";"):
                continue
            try:
                self._line(line)
            except ValueError as error:
                self.unknowns.append(f"line {number}: {error}")
        if self.block is not None and not self.block["terminated"]:
            self.unknowns.append(f"block {self.block['id']} has no parsed terminator")
        if self.function is not None:
            self._end_function()
        for function in self.functions:
            labels = {block["id"] for block in function["blocks"]}
            for edge in function["edges"]:
                if edge["source"] not in labels or edge["target"] not in labels:
                    self.unknowns.append(f"edge target/source missing: {edge['source']} -> {edge['target']}")
        return self.functions

    def _start_function(self, name):
        if self.function is not None:
            raise ValueError("nested function definitions are unsupported")
        self.function = {"id": name, "blocks": [], "edges": []}

    def _end_function(self):
        if self.block is not None:
            if not self.block["terminated"]:
                self.unknowns.append(f"block {self.block['id']} has no parsed terminator")
            if self.function is not None:
                self.function["blocks"].append(self.block)
            self.block = None
        if self.function is not None:
            self.functions.append(self.function)
            self.function = None

    def _start_block(self, label):
        if self.function is None:
            raise ValueError("basic block outside a function")
        if self.block is not None:
            if not self.block["terminated"]:
                self.unknowns.append(f"block {self.block['id']} has no parsed terminator")
            self.function["blocks"].append(self.block)
        self.block = {"id": label, "instructions": [], "terminated": False}

    def _instruction(self, line, edges=(), terminator=False):
        if self.function is None:
            return
        if self.block is None:
            self._start_block("entry")
        if self.block["terminated"]:
            raise ValueError("instruction follows a block terminator")
        self.block["instructions"].append(line)
        if terminator:
            self.block["terminated"] = True
            for target in edges:
                self.function["edges"].append({"source": self.block["id"], "target": target,
                                               "evidence": line})

    def _line(self, line):
        if self.format == "llvm":
            self._llvm(line)
        elif self.format == "mir":
            self._mir(line)
        else:
            self._mlir(line)

    def _llvm(self, line):
        if line.startswith("define "):
            if "@" not in line or "(" not in line:
                raise ValueError("malformed LLVM function definition")
            name = line.split("@", 1)[1].split("(", 1)[0].strip('"')
            self._start_function(name)
            return
        if line == "}":
            self._end_function()
            return
        if self.function is None:
            return
        if line.endswith(":") and " " not in line:
            self._start_block(line[:-1])
            return
        tokens = line.replace(",", " ").split()
        if tokens[:2] == ["br", "label"] and len(tokens) == 3:
            self._instruction(line, [tokens[2].removeprefix("%")], True)
        elif tokens[:2] == ["br", "i1"] and len(tokens) == 7 and tokens[3] == tokens[5] == "label":
            self._instruction(line, [tokens[4].removeprefix("%"), tokens[6].removeprefix("%")], True)
        elif tokens and tokens[0] in {"ret", "unreachable"}:
            self._instruction(line, terminator=True)
        elif tokens and tokens[0] in {"switch", "indirectbr", "invoke", "callbr", "resume", "catchswitch", "catchret", "cleanupret"}:
            raise ValueError(f"unsupported LLVM terminator {tokens[0]}")
        else:
            self._instruction(line)

    def _mir(self, line):
        if self.function is None and line != "}":
            self._start_function("mir_body")
        if line.startswith("bb") and ":" in line:
            self._start_block(line.split(":", 1)[0])
            if line.rstrip().endswith("{"):
                return
        if line == "}":
            if self.block is None:
                raise ValueError("MIR closing brace outside a basic block")
            if not self.block["terminated"]:
                self.unknowns.append(f"block {self.block['id']} has no parsed terminator")
            self.function["blocks"].append(self.block)
            self.block = None
            return
        if self.function is None:
            self._start_function("mir_body")
        if line.startswith("goto -> ") and line.endswith(";"):
            self._instruction(line, [line[len("goto -> "):-1].strip()], True)
        elif line == "return;":
            self._instruction(line, terminator=True)
        elif line.startswith("switchInt(") and "-> [" in line and line.endswith("];"):
            targets = []
            body = line.split("-> [", 1)[1][:-2]
            for arm in body.split(","):
                if ":" not in arm:
                    raise ValueError("malformed MIR switchInt arm")
                targets.append(arm.rsplit(":", 1)[1].strip())
            self._instruction(line, targets, True)
        elif line.startswith(("assert ", "drop ", "StorageLive", "StorageDead")) or line.startswith("_"):
            self._instruction(line)
        else:
            raise ValueError("unsupported MIR statement or terminator")

    def _mlir(self, line):
        if line.startswith("func.func "):
            if "@" not in line:
                raise ValueError("malformed MLIR function")
            name = line.split("@", 1)[1].split("(", 1)[0].split()[0]
            self._start_function(name)
            return
        if line == "}":
            self._end_function()
            return
        if self.function is None:
            return
        if line.startswith("^") and ":" in line:
            self._start_block(line[1:].split(":", 1)[0])
            return
        tokens = line.replace(",", " ").split()
        if len(tokens) == 2 and tokens[0] == "cf.br" and tokens[1].startswith("^"):
            self._instruction(line, [tokens[1][1:]], True)
        elif len(tokens) == 4 and tokens[0] == "cf.cond_br" and tokens[2].startswith("^") and tokens[3].startswith("^"):
            self._instruction(line, [tokens[2][1:], tokens[3][1:]], True)
        elif tokens and tokens[0] in {"func.return", "cf.assert"}:
            self._instruction(line, terminator=tokens[0] == "func.return")
        elif tokens and tokens[0].startswith("cf."):
            raise ValueError(f"unsupported MLIR control-flow operation {tokens[0]}")
        else:
            self._instruction(line)


def parse_compiler_ir(text, *, format, version, proof_mode=True) -> dict:
    """Parse explicit grammar-versioned functions, blocks, and CFG edges."""
    format = format.lower()
    key = (format, str(version))
    if key not in _GRAMMARS:
        return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown",
                "functions": [], "unknowns": [f"unsupported compiler IR grammar: {format} {version}"]}
    parser = _IRParser(format)
    try:
        functions = parser.parse(text)
    except Exception as error:
        parser.unknowns.append(f"IR parse failed: {type(error).__name__}: {error}")
        functions = parser.functions
    unknowns = sorted(set(parser.unknowns))
    return {"schema": SCHEMA, "schema_version": 1,
            "grammar": _GRAMMARS[key], "proof_mode": bool(proof_mode),
            "verdict": "unknown" if unknowns or not functions else "proved",
            "status": "unknown" if unknowns else "parsed",
            "functions": functions, "unknowns": unknowns,
            "source_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "scope": "parsed control-flow structure only; not semantic equivalence"}
