"""Sandboxed PythoC compilation worker; never imported by the PegRex parent."""
from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path
import sys


def main() -> int:
    source, ir_path, report_path = map(Path, sys.argv[1:4])
    entrypoint = sys.argv[4]
    try:
        import pythoc
        from importlib.metadata import version
        pythoc.init()
        spec = importlib.util.spec_from_file_location("pegrex_pythoc_candidate", source)
        if spec is None or spec.loader is None:
            raise ValueError("cannot create a PythoC module loader")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # Intentional operator-code execution inside the sandbox.
        if not hasattr(module, entrypoint):
            raise ValueError(f"entrypoint not found: {entrypoint}")
        pythoc.flush_all_pending_outputs()
        compiler = pythoc.get_compiler(str(source.resolve()))
        if compiler is None:
            raise ValueError("no PythoC compiler was registered for the source")
        ir_text = str(compiler.module)
        if not ir_text.strip():
            raise ValueError("PythoC emitted empty LLVM IR")
        pythoc.validate_ir(ir_text)
        ir_path.write_text(ir_text, encoding="utf-8")
        llvm = pythoc.get_llvm_version()
        report = {"schema": "pegrex.pythoc-worker.v1", "status": "compiled",
                  "entrypoint": entrypoint, "ir_file": ir_path.name,
                  "ir_sha256": hashlib.sha256(ir_text.encode()).hexdigest(),
                  "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                  "pythoc_module_version": str(getattr(pythoc, "__version__", "unknown")),
                  "pythoc_distribution_version": version("pythoc"),
                  "llvm_version": list(llvm) if isinstance(llvm, tuple) else str(llvm),
                  "llvm_ir_verified": True,
                  "verification_scope": "LLVM IR well-formedness only"}
        report_path.write_text(json.dumps(report, sort_keys=True), encoding="utf-8")
        return 0
    except Exception as error:
        report_path.write_text(json.dumps({
            "schema": "pegrex.pythoc-worker.v1", "status": "error",
            "error": f"{type(error).__name__}: {error}"}), encoding="utf-8")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
