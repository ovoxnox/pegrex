#!/usr/bin/env python
"""Dependency-free test runner; delegates to pytest when importable."""
import importlib
import importlib.util
import subprocess
import sys

MODULES = (
    "tests.test_api", "tests.test_apicontract", "tests.test_bridge",
    "tests.test_c11", "tests.test_cegis", "tests.test_chain",
    "tests.test_cobol", "tests.test_cognitive", "tests.test_compose",
    "tests.test_compress", "tests.test_concolic", "tests.test_contract",
    "tests.test_continuity", "tests.test_eggx", "tests.test_emitter",
    "tests.test_endpoints", "tests.test_expansion", "tests.test_extension",
    "tests.test_fortran", "tests.test_gaps", "tests.test_gaps2",
    "tests.test_go_client", "tests.test_gramir", "tests.test_grammars",
    "tests.test_hybridrag", "tests.test_idioms", "tests.test_invariants",
    "tests.test_ir", "tests.test_json", "tests.test_linsolve",
    "tests.test_loops", "tests.test_m10", "tests.test_m5", "tests.test_m6",
    "tests.test_m8", "tests.test_m9", "tests.test_marketplace",
    "tests.test_memory", "tests.test_mini_llm", "tests.test_nlspec",
    "tests.test_octagon", "tests.test_overflow", "tests.test_pdr",
    "tests.test_perfgolf", "tests.test_pipeline", "tests.test_prchat",
    "tests.test_proofs", "tests.test_python_frontend", "tests.test_rank",
    "tests.test_refine", "tests.test_registry", "tests.test_sca",
    "tests.test_gaps3", "tests.test_selfhost", "tests.test_selfplay", "tests.test_semantics",
    "tests.test_service", "tests.test_ship1", "tests.test_ship2",
    "tests.test_smt", "tests.test_specmine", "tests.test_sqlrel",
    "tests.test_strategies", "tests.test_summaries", "tests.test_tokenizer",
    "tests.test_tsmock", "tests.test_varpatterns", "tests.test_veritest",
    "tests.test_vm", "tests.test_vm_loops", "tests.test_workflow",
)


def main() -> int:
    if importlib.util.find_spec("pytest"): # richer reporting when present
        code = subprocess.call([sys.executable, "-m", "pytest",
                                "tests/", "-q", "--tb=short"])
        if code == 0:
            return 0       # fall through to shim on env quirks
    failures = 0
    for modname in MODULES:
        try:
            mod = importlib.import_module(modname)
        except Exception as e:
            # one unimportable/missing module must not sink the whole shim
            # (e.g. a same-named third-party package shadowing a namespace
            # package -- see tests/__init__.py, added to anchor this as a
            # real package and avoid exactly that collision)
            failures += 1
            print(f"FAIL {modname}: import error: {e!r}")
            continue
        for name in sorted(dir(mod)):
            if not name.startswith("test_"):
                continue
            try:
                getattr(mod, name)()
                print(f"PASS {modname}.{name}")
            except Exception as e:
                failures += 1
                print(f"FAIL {modname}.{name}: {e!r}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
