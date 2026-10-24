"""capabilities.py -- infer what a program can touch; emit least-privilege
manifests and sandbox policies."""
from __future__ import annotations

import re

CATALOG = [
    ("network", [r"\brequests\.", r"\burllib\b", r"\bsocket\b",
                 r"\bhttpx\b", r"fetch\("]),
    ("filesystem", [r"\bopen\s*\(", r"\bos\.(?:remove|makedirs|listdir)",
                    r"\bshutil\.", r"\bpathlib\b"]),
    ("process", [r"\bsubprocess\b", r"\bos\.system", r"\bexec[lv]e?p?\(",
                 r"\bPopen\("]),
    ("crypto", [r"\bhashlib\b", r"\bcryptography\b", r"\bssl\b"]),
    ("environment", [r"\bos\.environ", r"\bgetenv\("]),
]


def infer_capabilities(source: str) -> dict:
    """infer capabilities(source): see module docstring."""
    caps = {}
    for cap, patterns in CATALOG:
        hits = [p for p in patterns if re.search(p, source)]
        if hits:
            caps[cap] = sorted(hits)[:3]
    return caps


def to_sandbox_manifest(caps: dict) -> dict:
    """Least-privilege WASI/seccomp-style capability manifest (flat)."""
    table = {"network": ["socket", "connect"],
             "filesystem": ["openat", "read", "write"],
             "process": ["execve", "fork"],
             "crypto": ["getrandom"],
             "environment": []}
    flat = sorted({s for c in caps for s in table.get(c, [])})
    return {"wasi_preview1": sorted(caps.keys()), "seccomp": flat}
