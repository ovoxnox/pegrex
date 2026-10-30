"""Shared hard limits for untrusted source and analysis artifacts.

These limits are conservative defaults, not claims that every analyzer can
finish within them. Individual analyses may impose stricter budgets. Exceeding
a hard input limit must be reported as an explicit refusal/UNKNOWN upstream.
"""

MAX_SOURCE_BYTES = 2_000_000
MAX_AST_NODES = 250_000
MAX_ANALYSIS_OUTPUT_BYTES = 8_000_000
MAX_ARTIFACT_BYTES = 20_000_000

# Shared AnalysisSession report budget; individual analyzers may be stricter.
DEFAULT_ANALYSIS_TIMEOUT_MS = 30_000
MAX_ANALYSIS_PATHS = 10_000
