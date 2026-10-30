---
name: pegrex-engine
description: Use the production CoreEngine operation dispatcher, Tools API v2 manifests, and structured CLI for evidence-bearing PegRex integrations.
---

# production engine and tools

## Typed operation dispatch
    from pegrex import CoreEngine
    engine = CoreEngine()
    result = engine.execute("audit", {"path": "src/example.py"})

`execute` returns an `OperationResult` with `operation`, `status`, `verdict`,
`data`, `unknowns`, `assumptions`, and `metadata`. Expected validation and
operation failures are values, not CLI tracebacks. Unknown operations fail
closed. Check `status` and `verdict` before using `data`; UNKNOWN is not clean
evidence.

List supported operations with `engine.operations()` or:

    python pegrex.py engine list
    python pegrex.py engine audit --input '{"path":"src/example.py"}'

## Tools API v2
    from pegrex.toolsapi import invoke, list_tools
    manifest = list_tools()
    result = invoke("core.audit", {"path": "src/example.py"}, workspace=".")

    python pegrex.py tools
    python pegrex.py tool core.audit --input '{"path":"src/example.py"}'

Manifests publish JSON-shaped argument schemas. Invocation validates arguments,
confirms workspace confinement (including symlinks), and preserves evidence
status. Results are dictionaries with `status`, `verdict`, `data`, `unknowns`,
and `provenance`. Missing evidence, unavailable dependency intelligence, parser
gaps, and resource limits remain UNKNOWN. Never convert an error or UNKNOWN
result into a successful clean audit. Only tools marked `mutates_workspace: true`
write, and only beneath declared confined staging roots.

## Optional external backends

Use `neural.generate` / `neural.verify_candidate` for staged neural-codegen Rust
candidates, `ironkernel.run` / `ironkernel.differential` for bounded JSON float64
expressions, and `pythoc.compile` / `pythoc.analyze_ir` / `pythoc.differential`
for sandboxed native compilation and explicit LLVM 17/18 analysis. Equivalent
CLI subgroups are `neural`, `ironkernel`, and `pythoc`.

These adapters return `pegrex.integration-result.v1`. Generation and compilation
produce candidates, not PROVED implementations. Matching sampled differentials
remain UNKNOWN for general equivalence; mismatches require confirmed replay.
PythoC compilation and native execution require an ephemeral no-network sandbox.
Never pass arbitrary Python source to the ironkernel expression worker. Check
artifact hashes and preserve backend/toolchain provenance in assurance claims.

## Compatibility and trust

Legacy `pegrex.api` functions and default CLI output remain supported beside
these interfaces. Candidate code is not published code until independently
verified. Execution-bearing concolic, certificate, PoC, and broker interfaces
are explicit operator-code-execution boundaries, not passive analyzers.
