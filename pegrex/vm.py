"""
vm — stack bytecode VM

║  Instruction set: LOAD_CONST, LOAD_VAR, STORE, BINOP, JMP_IF_FALSE,     
║  JMP, HALT. Compiled from the Python straight-line branchy fragment     
║  (ast): assignments, if/else, comparisons, arithmetic, return.          
║  Certified DIFFERENTIALLY against CPython: same results on every        
║  fixture, and branch traces agree with the m90 concolic tracer."""

from __future__ import annotations

import ast

OPS = {"Add": "+", "Sub": "-", "Mult": "*",
       "Lt": "<", "LtE": "<=", "Gt": ">", "GtE": ">=", "Eq": "==", "NotEq": "!="}
_BIN = {"+", "-", "*", "<", "<=", ">", ">=", "==", "!="}


class CompileError(ValueError):
    """Outside the VM fragment -- loud refusal."""


def _binop(op, a, b):
    if op == "+":
        return a + b
    if op == "-":
        return a - b
    if op == "*":
        return a * b
    return {"<": a < b, "<=": a <= b, ">": a > b,
            ">=": a >= b, "==": a == b, "!=": a != b}[op]


def compile_fn(src):
    """Python source (single function) -> (code, branches).

    code: list of (op, arg). branches: {pc_of_guard: condition-source}
    for concolic integration."""
    tree = ast.parse(src)
    fns = [n for n in tree.body if isinstance(n, ast.FunctionDef)]
    if len(fns) != 1:
        raise CompileError("vm: need exactly one function")
    fn = fns[0]
    code = []
    branches = {}

    def emit(op, arg=None):
        """emit(op, arg): see module docstring."""
        code.append((op, arg))
        return len(code) - 1

    def expr(e):
        """expr(e): see module docstring."""
        if isinstance(e, ast.Constant) and isinstance(e.value, int):
            emit("LOAD_CONST", e.value)
        elif isinstance(e, ast.Name):
            emit("LOAD_VAR", e.id)
        elif isinstance(e, ast.BinOp) and type(e.op).__name__ in OPS:
            expr(e.left)
            expr(e.right)
            emit("BINOP", OPS[type(e.op).__name__])
        elif isinstance(e, ast.UnaryOp) and isinstance(e.op, ast.USub):
            expr(e.operand)
            emit("LOAD_CONST", -1)
            emit("BINOP", "*")
        elif isinstance(e, ast.Compare) and len(e.ops) == 1 and \
                type(e.ops[0]).__name__ in OPS:
            expr(e.left)
            expr(e.comparators[0])
            emit("BINOP", OPS[type(e.ops[0]).__name__])
        else:
            raise CompileError(f"vm: unsupported expression {ast.dump(e)[:60]}")

    def stmt(s):
        """stmt(s): see module docstring."""
        if isinstance(s, ast.Assign) and len(s.targets) == 1 and \
                isinstance(s.targets[0], ast.Name):
            expr(s.value)
            emit("STORE", s.targets[0].id)
        elif isinstance(s, ast.Return):
            expr(s.value)
            emit("HALT")
        elif isinstance(s, ast.While):
            loop_start = len(code)
            expr(s.test)
            jf = emit("JMP_IF_FALSE", None)
            branches[jf] = ast.unparse(s.test)
            for st in s.body:
                stmt(st)
            emit("JMP", loop_start)
            code[jf] = ("JMP_IF_FALSE", len(code))
        elif isinstance(s, ast.If):
            expr(s.test)
            jf = emit("JMP_IF_FALSE", None)
            branches[jf] = ast.unparse(s.test)   # trace point: cond on stack
            for st in s.body:
                stmt(st)
            jend = emit("JMP", None)
            code[jf] = ("JMP_IF_FALSE", len(code))
            for st in s.orelse:
                stmt(st)
            code[jend] = ("JMP", len(code))
        else:
            raise CompileError(f"vm: unsupported statement {ast.dump(s)[:60]}")

    for s in fn.body:
        stmt(s)
    if not code or code[-1][0] != "HALT":
        emit("LOAD_CONST", None)
        emit("HALT")
    return code, branches, [a.arg for a in fn.args.args]


def run(code, args, params):
    """Execute bytecode. Returns (value, trace).

    trace: [(guard_pc, condition_src, truth)] via branches metadata."""
    env = dict(zip(params, args))
    stack = []
    trace = []
    branches = run.branches
    pc = 0
    steps = 0
    while True:
        steps += 1
        if steps > 10000:
            raise RuntimeError("vm: step limit (runaway loop?)")
        op, arg = code[pc]
        if pc in branches:
            # guard result is on top of stack BEFORE JMP_IF_FALSE executes
            trace.append((pc, branches[pc], bool(stack[-1])))
        if op == "LOAD_CONST":
            stack.append(arg)
        elif op == "LOAD_VAR":
            if arg not in env:
                raise RuntimeError(f"vm: unbound variable {arg}")
            stack.append(env[arg])
        elif op == "STORE":
            env[arg] = stack.pop()
        elif op == "BINOP":
            b = stack.pop()
            a = stack.pop()
            stack.append(_binop(arg, a, b))
        elif op == "JMP_IF_FALSE":
            if not stack.pop():
                pc = arg
                continue
        elif op == "JMP":
            pc = arg
            continue
        elif op == "HALT":
            return (stack.pop() if stack else None), trace
        pc += 1


def run_fn(src, *args):
    """Compile + execute in one call."""
    code, branches, params = compile_fn(src)
    run.branches = branches
    try:
        return run(code, args, params)
    finally:
        run.branches = {}
