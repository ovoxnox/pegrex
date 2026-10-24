"""
wire - front-controller framing seam for the protocol endpoints.

One framing layer, pluggable codecs: JSON-lines (A2A) and LSP
Content-Length framing share handler dispatch -- no duplicated framing
loops in the endpoints. temp_source is the other piece every endpoint
needed: a request can carry inline source text instead of an existing
path, so it has to land on disk for the engine's path-based API -- one
place that does this and always cleans up, instead of each endpoint
reimplementing mkstemp (a2a.py's own copy never even unlinked the file).
"""
from __future__ import annotations

import contextlib
import json
import os
import tempfile


@contextlib.contextmanager
def temp_source(src: str, suffix: str = ".py"):
    """Write `src` to a scratch file for the duration of the block, then
    remove it. Use when a request carries inline source text rather than
    a path the engine can read directly:

        with temp_source(params["source"]) as path:
            return api.contracts(path)
    """
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w") as f:
        f.write(src)
    try:
        yield path
    finally:
        os.unlink(path)



def serve_jsonlines(handle, stream_in, stream_out):
    """One JSON object per line; malformed lines get an error response."""
    for line in stream_in:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            msg = None
        stream_out.write(json.dumps(handle(msg)) + "\n")
        stream_out.flush()


def serve_lsp(handle, stream_in, stream_out):
    """Content-Length framed loop."""
    while True:
        headers = {}
        while True:
            line = stream_in.readline()
            if not line:
                return
            line = line.strip()
            if not line:
                break
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        try:
            length = int(headers["content-length"])
        except (KeyError, ValueError):
            continue
        body = stream_in.read(length)
        try:
            msg = json.loads(body)
        except json.JSONDecodeError:
            msg = None
        payload = json.dumps(handle(msg)).encode()
        stream_out.write(("Content-Length: %d\r\n\r\n" % len(payload)).encode())
        stream_out.write(payload)
        stream_out.flush()
