"""
a2a — agent-to-agent protocol endpoint
JSON-RPC 2.0-shaped messages, stdio-friendly, alongside ACP/MCP.
Methods: contracts, audit, verify_patch, semantic_diff, refine.
Malformed messages get a JSON-RPC error -- refused, never crashed."""
from __future__ import annotations

import contextlib
import json

from . import api
from .semantics import semantic_diff, verify_patch
from .refine import discharge_source, parse_contracts
from .wire import temp_source

_METHODS = ("contracts", "audit", "verify_patch", "semantic_diff", "refine")

@contextlib.contextmanager
def _resolve_path(params, path_key, source_key):
    """Use params[path_key] directly if given (an existing file -- never
    deleted), else write params[source_key] to a scratch file for the
    duration of the block (wire.temp_source, which always cleans up --
    this endpoint's own mkstemp copy never used to)."""
    existing = params.get(path_key)
    if existing:
        yield existing
    else:
        with temp_source(params[source_key]) as p:
            yield p

def _contracts(params):
    with _resolve_path(params, "path", "source") as path:
        return [{"constraints": sorted(map(str, cs)), "result": str(r)}
                for cs, r in api.contracts(path)]

def _audit(params):
    with _resolve_path(params, "path", "source") as path:
        return api.audit(path)

def _verify_patch(params):
    with _resolve_path(params, "before_path", "before") as a, \
         _resolve_path(params, "after_path", "after") as b:
        return verify_patch(a, b, params.get("claim", "equivalent"))

def _semantic_diff(params):
    with _resolve_path(params, "a_path", "a") as a, \
         _resolve_path(params, "b_path", "b") as b:
        return semantic_diff(a, b)

def _refine(params):
    with _resolve_path(params, "path", "source") as path:
        return discharge_source(path, parse_contracts(params.get("source", "")))

_HANDLERS = {"contracts": _contracts, "audit": _audit,
             "verify_patch": _verify_patch, "semantic_diff": _semantic_diff,
             "refine": _refine}

def handle(message) -> dict:
    """One JSON-RPC message in, one response out. Never raises."""
    if not isinstance(message, dict):
        return {"jsonrpc": "2.0", "id": None,
                "error": {"code": -32600, "message": "invalid request"}}
    mid = message.get("id")
    method = message.get("method")
    if method not in _METHODS:
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32601, "message": f"unknown method {method!r}"}}
    params = message.get("params") or {}
    if not isinstance(params, dict):
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32602, "message": "params must be an object"}}
    try:
        result = _HANDLERS[method](params)
    except (KeyError, ValueError, TypeError) as e:
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32602, "message": str(e)[:200]}}
    except Exception as e: # never crash the endpoint
        return {"jsonrpc": "2.0", "id": mid,
                "error": {"code": -32603, "message": f"{type(e).__name__}: {e}"[:200]}}
    return {"jsonrpc": "2.0", "id": mid, "result": result}

def serve(stream_in, stream_out) -> None:
    """stdio server: one JSON object per line (JSON-lines framing via wire)."""
    from .wire import serve_jsonlines
    serve_jsonlines(handle, stream_in, stream_out)
