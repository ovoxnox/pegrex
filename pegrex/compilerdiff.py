"""Differential verification for compiler upgrades and optimization changes."""
from __future__ import annotations
import hashlib, tempfile
from pathlib import Path
from .semantics import verify_patch
SCHEMA = "pegrex.compiler-differential.v1"


def verify_compiler_change(source, baseline_compiler, candidate_compiler) -> dict:
    """Compilers return complete Python artifact source for semantic comparison.

    Non-Python or unverifiable artifacts remain UNKNOWN; no output-text match is
    promoted to semantic proof. Metadata can identify upgrades/optimization flags.
    """
    identity = hashlib.sha256(source.encode()).hexdigest()
    try:
        baseline = baseline_compiler(source)
        candidate = candidate_compiler(source)
        if not isinstance(baseline, str) or not isinstance(candidate, str): raise TypeError("compilers must return source text")
    except Exception as error:
        return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown",
                "source_sha256": identity, "artifacts": {}, "certificate": None,
                "unknowns": [f"compiler execution failed: {error}"]}
    with tempfile.TemporaryDirectory(prefix="pegrex-compiler-") as workspace:
        before, after = Path(workspace)/"baseline.py", Path(workspace)/"candidate.py"
        before.write_text(baseline, encoding="utf-8"); after.write_text(candidate, encoding="utf-8")
        try: result = verify_patch(str(before), str(after))
        except Exception as error:
            return {"schema": SCHEMA, "schema_version": 1, "verdict": "unknown",
                    "source_sha256": identity, "certificate": None, "unknowns": [str(error)]}
    confirmed = bool((result.get("counterexample") or {}).get("confirmed") is True)
    verdict = "proved" if result.get("verified") is True else "refuted" if confirmed else "unknown"
    return {"schema": SCHEMA, "schema_version": 1, "verdict": verdict,
            "source_sha256": identity,
            "artifacts": {"baseline_sha256": hashlib.sha256(baseline.encode()).hexdigest(),
                          "candidate_sha256": hashlib.sha256(candidate.encode()).hexdigest()},
            "verification": result, "unknowns": [] if verdict != "unknown" else [result.get("note", "compiler equivalence undecided")]}
