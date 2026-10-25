"""Shared command-handler helpers."""
from __future__ import annotations

import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


def _expand(path: str, suffixes=(".py",)) -> list:
    """Expand a file or directory recursively to matching source files."""
    p = pathlib.Path(path)
    if p.is_dir():
        return sorted(f for f in p.rglob("*") if f.suffix in suffixes
                      and "__pycache__" not in str(f) and ".vendor" not in str(f))
    return [p]


def _emit_json(obj):
    import json
    print(json.dumps(obj, indent=1, default=str))
