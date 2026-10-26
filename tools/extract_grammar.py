#!/usr/bin/env python
"""extract_grammar.py -- pull grammar text verbatim from upstream lpegrex
parser files, eliminating hand-transcription errors.

Usage:
  python tools/extract_grammar.py <upstream.*> <out.gram>   # extract
  python tools/extract_grammar.py --check                     # diff all

Extraction: upstream parsers are *lang files whose grammar lives in a
long-bracket string ([==[ ... ]==]).  We take that block byte-for-byte.
Run grammar_lint.py on the result, then compile with pegrex.
"""
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).parent.parent
EXAMPLES = HERE / "examples"


def extract(lua_path):
    text = pathlib.Path(lua_path).read_text(encoding="utf-8")
    m = re.search(r"\[(=*)\[(.*?)\]\1\]", text, re.S)
    if not m:
        raise SystemExit(f"no long-bracket block in {lua_path}")
    return m.group(2).strip() + "\n"


def main(argv):
    if len(argv) >= 3:
        out = extract(argv[1])
        pathlib.Path(argv[2]).write_text(out, encoding="utf-8")
        print(f"wrote {argv[2]} ({len(out.splitlines())} lines)")
        return 0
    # --check: re-extract any upstream file placed in examples/upstream/
    up = EXAMPLES / "upstream"
    if not up.exists():
        print("place upstream parsers/*. in examples/upstream/ to --check")
        return 0
    bad = 0
    for lua in sorted(up.glob("*.lua")):
        gram = EXAMPLES / (lua.stem + ".gram")
        if not gram.exists():
            print(f"MISSING {gram.name}")
            bad += 1
            continue
        if extract(lua) != gram.read_text(encoding="utf-8"):
            print(f"DIFFERS {gram.name}")
            bad += 1
        else:
            print(f"OK      {gram.name}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
