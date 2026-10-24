"""
budget.py -- complexity budgets as contract invariants.
A module exceeding its budget fails the gate -- the codebase stops
growing by accident.  Thresholds live in the manifest (contract discipline).
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Budget:
    """Budget - see module docstring."""
    max_loc: int = 300
    max_function_lines: int = 40
    min_docstring_ratio: float = 0.0  # 0..1 of public functions
    findings: list = field(default_factory=list)

    def check(self, path, src: str, fn_lines: dict | None = None,
              doc_ratio: float | None = None) -> "Budget":
        loc = src.count(chr(10)) + 1
        if loc > self.max_loc:
            self.findings.append(
                f"{path}: {loc} LOC exceeds budget {self.max_loc}")
        for fn, lines in (fn_lines or {}).items():
            if lines > self.max_function_lines:
                self.findings.append(
                    f"{path}: {fn} is {lines} lines "
                    f"(budget {self.max_function_lines})")
        if doc_ratio is not None and doc_ratio < self.min_docstring_ratio:
            self.findings.append(
                f"{path}: docstring ratio {doc_ratio:.2f} "
                f"< {self.min_docstring_ratio:.2f}")
        return self

    @property
    def passed(self) -> bool:
        return not self.findings
