"""mkspec -- multi-opus AI spec generator.

Analyzers find facts (security, structure, smells, tests, docs, deps).
Opus are perspectives that turn facts into prioritized agent tasks.
Templates define the output schema. All three are pluggable:

    from mkspec.core import analyzer, opus
    @analyzer("my-check")
    def my_check(ctx): ...
    @opus("my-opus")
    def my_opus(ctx, facts): ...
"""
from .core import (analyzer, opus, Finding, AnalysisContext,   # noqa: F401
                   run_analyzers, run_opus, render_spec, main)
