"""Optional, fail-closed adapters for external generation and execution backends.

No backend is imported by the stable PegRex core. Generated and compiled code is
always a candidate until an independently scoped verification gate accepts it.
"""

SCHEMA = "pegrex.integration-result.v1"
REQUEST_SCHEMA = "pegrex.integration-request.v1"

__all__ = ["SCHEMA", "REQUEST_SCHEMA"]
