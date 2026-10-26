"""Contract-preserving legacy modernization with explicit numeric/layout scope."""
from __future__ import annotations

import os
import tempfile
from pathlib import Path

from . import api
from .emitter import emit_python
from .modernize import _legacy_fn_name, _legacy_params
from .semantics import verify_patch

SCHEMA = "pegrex.contract-modernization.v1"


def _target_expression(text, target):
    value = str(text)
    if target in {"rust", "go"}:
        value = value.replace(" and ", " && ").replace(" or ", " || ")
        if value.startswith("not "):
            value = "!(" + value[4:] + ")"
    return value


def emit_modern_target(name, params, contracts, target, numeric=None):
    """Emit the same exhaustive branch fragment used by the Python emitter."""
    numeric = numeric or {}
    bits = numeric.get("bits", 64)
    signed = numeric.get("signed", True)
    if target == "python":
        return emit_python(name, params, contracts)
    if target not in {"rust", "go"}:
        raise ValueError("target must be Python, Rust, or Go")
    if target == "rust":
        if bits not in {8, 16, 32, 64, 128}:
            raise ValueError("unsupported Rust integer width")
        integer = ("i" if signed else "u") + str(bits)
        lines = [f"pub fn {name}({', '.join(f'{p}: {integer}' for p in params)}) -> {integer} {{"]
    else:
        if bits not in {8, 16, 32, 64}:
            raise ValueError("unsupported Go integer width")
        integer = ("int" if signed else "uint") + str(bits)
        lines = [f"func {name}({', '.join(f'{p} {integer}' for p in params)}) {integer} {{"]
    paths = [(sorted(cs, key=str), result) for cs, result in contracts]
    if not paths:
        raise ValueError("no contracts to emit")
    for index, (constraints, result) in enumerate(paths):
        condition = " && ".join("(" + _target_expression(row, target) + ")" for row in constraints)
        if target == "go":
            lines.append(f"    if {condition or 'true'} {{")
            lines.append(f"        return {_target_expression(result, target)};")
            lines.append("    }")
            continue
        if index == 0:
            lines.append(f"    if {condition or 'true'} {{")
        elif constraints:
            lines.append(f"    }} else if {condition} {{")
        else:
            lines.append("    } else {")
        lines.append(f"        return {_target_expression(result, target)};")
    if target != "go":
        lines.append("    }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _numeric_evidence(target, numeric):
    if not isinstance(numeric, dict):
        return {"verdict": "unknown", "unknowns": ["numeric width, signedness, and overflow semantics were not declared"]}
    required = {"bits", "signed", "overflow"}
    if not required <= set(numeric):
        return {"verdict": "unknown", "declared": numeric,
                "unknowns": ["numeric declaration requires bits, signed, and overflow"]}
    overflow = numeric["overflow"]
    if overflow not in {"unbounded", "wrap", "trap", "saturate"}:
        return {"verdict": "unknown", "declared": numeric, "unknowns": ["unsupported overflow declaration"]}
    if target == "python":
        verdict = "proved" if overflow == "unbounded" else "refuted"
        note = "Python integers are unbounded" if verdict == "proved" else "Python emission does not implement fixed-width overflow semantics"
    elif target == "go":
        if overflow == "wrap":
            verdict, note = "proved", "Go integer overflow semantics are scoped to the declared fixed-width type"
        else:
            verdict, note = "refuted", "plain Go integer arithmetic does not implement the declared overflow semantics"
    else:
        verdict, note = "unknown", "Rust plain integer overflow differs by build profile; explicit checked/wrapping lowering is required"
    return {"verdict": verdict, "declared": numeric, "scope": note,
            "unknowns": [note] if verdict == "unknown" else []}


def _layout_evidence(layout):
    if layout is None:
        return {"verdict": "unknown", "unknowns": ["source and target data layout were not declared"]}
    ranges = []
    for field in layout:
        try:
            offset, size = field["offset"], field["size"]
            alignment = field.get("alignment", 1)
            if min(offset, size, alignment) < 0 or size == 0 or alignment == 0 or offset % alignment:
                raise ValueError("invalid field offset, size, or alignment")
            ranges.append((offset, offset + size, field["name"]))
        except (KeyError, TypeError, ValueError) as error:
            return {"verdict": "unknown", "unknowns": [f"invalid data-layout declaration: {error}"]}
    ranges.sort()
    for left, right in zip(ranges, ranges[1:]):
        if left[1] > right[0]:
            return {"verdict": "refuted", "unknowns": [],
                    "reason": f"overlapping fields: {left[2]} and {right[2]}"}
    if ranges:
        return {"verdict": "unknown", "fields": len(ranges),
                "unknowns": ["layout declarations are validated, but target record lowering is not proved"]}
    return {"verdict": "proved", "fields": 0, "scope": "explicitly no shared data-layout records", "unknowns": []}


def modernize_preserving_contracts(source_path, target="python", *, numeric=None,
                                   layout=None, copydir=None) -> dict:
    """Modernize COBOL/Fortran and retain independent three-valued evidence.

    Code may be returned with UNKNOWN numeric/layout evidence; it is never
    promoted to a fully contract-preserving result until every selected proof
    succeeds. Rust/Go emission uses their declared fixed-width integer type.
    """
    target = target.lower()
    source_path = Path(source_path)
    temporary = None
    try:
        source = source_path.read_text(encoding="utf-8")
        if source_path.suffix.lower() not in {".cob", ".cbl", ".cobol", ".f", ".f90", ".f95", ".f03", ".f08"}:
            raise ValueError("modernization input must be COBOL or Fortran")
        if copydir is not None and source_path.suffix.lower() in {".cob", ".cbl", ".cobol"}:
            from .cobolfront import expand_copybooks
            source = expand_copybooks(source, copydir)
            handle, expanded = tempfile.mkstemp(suffix=source_path.suffix)
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                stream.write(source)
            source_path = Path(expanded)
            temporary = Path(expanded)
        contracts = api.contracts(str(source_path))
        params = _legacy_params(contracts)
        name = _legacy_fn_name(source, source_path)
        code = emit_modern_target(name, params, contracts, target, numeric)
        suffix = {"python": ".py", "rust": ".rs", "go": ".go"}[target]
        handle, output = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(code)
        try:
            contract_proof = verify_patch(str(source_path), output)
        finally:
            os.unlink(output)
        contract_verdict = ("proved" if contract_proof.get("verified") is True else
                            "refuted" if (contract_proof.get("counterexample") or {}).get("confirmed") else "unknown")
        numeric_evidence = _numeric_evidence(target, numeric)
        layout_evidence = _layout_evidence(layout)
        verdicts = [contract_verdict, numeric_evidence["verdict"], layout_evidence["verdict"]]
        verdict = "refuted" if "refuted" in verdicts else "unknown" if "unknown" in verdicts else "proved"
        unknowns = list(numeric_evidence.get("unknowns", [])) + list(layout_evidence.get("unknowns", []))
        if contract_verdict == "unknown":
            unknowns.append("cross-language contract equality was not proved")
        return {"schema": SCHEMA, "schema_version": 1, "target": target,
                "function": name, "code": code, "verdict": verdict,
                "verified": verdict == "proved", "contract_evidence": {
                    "verdict": contract_verdict, "proof": contract_proof},
                "numeric_evidence": numeric_evidence, "layout_evidence": layout_evidence,
                "unknowns": unknowns, "counterexample": contract_proof.get("counterexample")}
    except Exception as error:
        return {"schema": SCHEMA, "schema_version": 1, "target": target,
                "code": None, "verdict": "unknown", "verified": False,
                "unknowns": [f"modernization failed: {type(error).__name__}: {error}"]}
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
