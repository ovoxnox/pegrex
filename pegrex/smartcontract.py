"""Separated Solidity source, EVM bytecode, formal, and local-test evidence."""
from __future__ import annotations

import hashlib
import re

SCHEMA = "pegrex.smart-contract-evidence.v1"


def check_contract_source(source) -> dict:
    """Run explicitly heuristic source checks; absence is not a proof."""
    findings = []
    try:
        if re.search(r"\btx\s*\.\s*origin\b", source):
            findings.append({"id": "SOL-TX-ORIGIN", "evidence": "tx.origin authorization requires review"})
        if re.search(r"\bselfdestruct\s*\(", source):
            findings.append({"id": "SOL-SELFDESTRUCT", "evidence": "selfdestruct is present"})
        lines = source.splitlines()
        for index, line in enumerate(lines):
            if re.search(r"\.(?:call|delegatecall|send|transfer)\s*(?:\{|\()", line):
                following = "\n".join(lines[index + 1:index + 5])
                if not re.search(r"\w+\s*(?:=|\+=|-=|\+\+|--)", following):
                    findings.append({"id": "SOL-EXTERNAL-CALL-ORDER", "line": index + 1,
                                     "evidence": "external call without a following state update in the local source window"})
        return {"status": "completed", "verdict": "refuted" if findings else "unknown",
                "findings": findings, "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                "unknowns": [] if findings else ["source-pattern absence is not a formal safety proof"],
                "scope": "source-level heuristic checks only"}
    except Exception as error:
        return {"status": "unknown", "verdict": "unknown", "findings": [],
                "unknowns": [f"source analysis failed: {error}"]}


def check_evm_bytecode(bytecode) -> dict:
    """Disassemble PUSH widths correctly before checking opcode presence."""
    try:
        text = bytecode.removeprefix("0x")
        if len(text) % 2 or not text or any(character not in "0123456789abcdefABCDEF" for character in text):
            raise ValueError("bytecode must be nonempty, even-length hexadecimal")
        data = bytes.fromhex(text)
        opcodes, push_data = [], []
        pc = 0
        while pc < len(data):
            opcode = data[pc]
            opcodes.append({"pc": pc, "opcode": opcode})
            pc += 1
            if 0x60 <= opcode <= 0x7f:
                width = opcode - 0x5f
                if pc + width > len(data):
                    raise ValueError("truncated PUSH immediate")
                push_data.append({"pc": pc, "bytes": width})
                pc += width
        names = {0xf1: "CALL", 0xf2: "CALLCODE", 0xf4: "DELEGATECALL", 0xff: "SELFDESTRUCT"}
        findings = [{"id": "EVM-" + names[row["opcode"]], "pc": row["pc"]}
                    for row in opcodes if row["opcode"] in names]
        return {"status": "completed", "verdict": "refuted" if findings else "unknown",
                "findings": findings, "instructions": len(opcodes), "push_data": push_data,
                "bytecode_sha256": hashlib.sha256(data).hexdigest(),
                "unknowns": [] if findings else ["opcode absence is not a formal bytecode safety proof"],
                "scope": "bytecode disassembly and selected opcode checks"}
    except Exception as error:
        return {"status": "unknown", "verdict": "unknown", "findings": [],
                "unknowns": [f"bytecode analysis failed: {error}"]}


def evaluate_formal_claims(claims) -> dict:
    """Implement evaluate formal claims with the module's explicit API and failure semantics."""
    rows = []
    for claim in claims:
        verdict = claim.get("verdict", "unknown")
        if verdict == "proved" and not claim.get("proof"):
            verdict = "unknown"
        if verdict == "refuted" and not (claim.get("counterexample") or {}).get("confirmed"):
            verdict = "unknown"
        if verdict not in {"proved", "refuted", "unknown"}:
            verdict = "unknown"
        rows.append({"id": claim.get("id"), "statement": claim.get("statement"),
                     "verdict": verdict, "proof": claim.get("proof"),
                     "counterexample": claim.get("counterexample"),
                     "unknowns": [] if verdict != "unknown" else ["formal claim lacks independently checkable evidence"]})
    return {"verdict": "refuted" if any(row["verdict"] == "refuted" for row in rows)
                       else "unknown" if not rows or any(row["verdict"] == "unknown" for row in rows)
                       else "proved", "claims": rows,
            "scope": "declared claims only; not source or bytecode agreement"}


def run_local_evm_tests(bytecode, tests, runner=None) -> dict:
    """Use a caller-supplied local EVM; never substitute a remote node."""
    if runner is None:
        return {"status": "unknown", "verdict": "unknown", "executed": False,
                "results": [], "unknowns": ["local EVM runner unavailable"]}
    try:
        report = runner(bytecode, list(tests))
        if not isinstance(report, dict) or not report.get("executed") or not report.get("local"):
            raise ValueError("runner did not confirm local EVM execution")
        results = list(report.get("results") or [])
        expected = len(tests)
        if len(results) != expected:
            raise ValueError("local EVM result count differs from test count")
        failed = [row for row in results if row.get("passed") is False]
        incomplete = [row for row in results if row.get("passed") not in {True, False}]
        verdict = "refuted" if failed else "unknown" if incomplete or not results else "proved"
        return {"status": "completed", "verdict": verdict, "executed": True,
                "local": True, "backend": report.get("backend", "local-evm"),
                "results": results, "unknowns": [] if results and not incomplete else ["no complete local EVM test evidence"],
                "scope": "supplied tests on a local EVM only"}
    except Exception as error:
        return {"status": "unknown", "verdict": "unknown", "executed": False,
                "results": [], "unknowns": [f"local EVM execution failed: {error}"]}


def analyze_smart_contract(*, source=None, bytecode=None, formal_claims=(),
                           local_tests=(), evm_runner=None) -> dict:
    """Implement analyze smart contract with the module's explicit API and failure semantics."""
    sections = {
        "source": check_contract_source(source) if source is not None else {
            "status": "unknown", "verdict": "unknown", "unknowns": ["source not supplied"]},
        "bytecode": check_evm_bytecode(bytecode) if bytecode is not None else {
            "status": "unknown", "verdict": "unknown", "unknowns": ["bytecode not supplied"]},
        "formal": evaluate_formal_claims(formal_claims),
        "local_evm": run_local_evm_tests(bytecode, local_tests, evm_runner),
    }
    verdict = ("refuted" if any(row.get("verdict") == "refuted" for row in sections.values())
               else "unknown")
    unknowns = [f"{name}: {reason}" for name, row in sections.items()
                for reason in row.get("unknowns", [])]
    return {"schema": SCHEMA, "schema_version": 1, "verdict": verdict,
            "sections": sections, "unknowns": unknowns,
            "scope": "evidence layers remain separate; no deployment or legal-safety conclusion"}
