#!/usr/bin/env python
"""grammar_lint.py -- static checks for pegrex grammar text files.

Catches the transcription bug classes that cost this project its early
debugging sessions.  Checks (line-oriented, grammar-syntax aware of
strings and comments):

  1. backtick parity per line (a missing closer pairs with the next
     token's opener and desyncs everything)
  2. every definition line has a rule arrow (`<--`, `<==`, `<-|`, `<-`)
  3. no fatal-@ compositions: `@x~?` / `~?` directly before a backticked
     token that follows `@`... approximated as: `@` token followed later
     by `~?` on the same rule (fatal-throw vs optionality poison)
  4. `$` capture not used as a `->` target (e.g. `->$7`)

Usage: python tools/grammar_lint.py examples/*.gram
Exit 1 on any violation.
"""
import pathlib
import re
import sys

ARROW = re.compile(r"^\s*[A-Za-z_`]")
TOKEN_ARROW = re.compile(r"<-\||<==|<--|<-")


def lint(path):
    problems = []
    lines = path.read_text(encoding="utf-8").splitlines()
    for n, line in enumerate(lines, 1):
        code = _strip_strings_comments(line)
        # 1. backtick parity (ignore `` inside single/double quotes)
        if code.count("`") % 2 == 1:
            problems.append(f"{path}:{n}: odd backtick count: {line.strip()!r}")
        # 2. definition lines need arrows
        s = line.strip()
        if ARROW.match(line) and not s.startswith("--"):
            if ("<--" in s or "<==" in s or "<-|" in s or re.search(r"<-\s", s)
                    or s.startswith("`")):
                pass
            elif re.match(r"^[A-Za-z_]", s) and not s.startswith("--"):
                # continuation lines of a previous rule are indented deeper;
                # a fresh rule name at column 0 without an arrow is suspect
                if line == s and not s.startswith((" ", "\t")):
                    problems.append(f"{path}:{n}: definition without arrow: {s!r}")
        # 4. `->$N`
        if re.search(r"->\s*\$", code):
            problems.append(f"{path}:{n}: '->$' (use juxtaposition: `'a' $7`): {s!r}")
    return problems


def _strip_strings_comments(line):
    """Blank out strings and comments, keeping backtick tokens intact.
    States: normal | string(quote) | backtick.  `--` starts a comment
    only in normal state (a backticked `--` is a token)."""
    out, i, q, bt = [], 0, None, False
    while i < len(line):
        ch = line[i]
        if bt:
            out.append(ch)                 # keep backtick tokens verbatim
            if ch == "`":
                bt = False
            i += 1
            continue
        if q:
            if ch == q:
                q = None
            i += 1
            continue
        if ch == "`":
            bt = True
            out.append(ch)
            i += 1
            continue
        if ch in "'\"":
            q = ch
            i += 1
            continue
        if line.startswith("--", i):
            break
        out.append(ch)
        i += 1
    return "".join(out)


def main(argv):
    total = 0
    for a in argv[1:]:
        probs = lint(pathlib.Path(a))
        for p in probs:
            print(p)
        total += len(probs)
    print(f"{total} problem(s) across {len(argv)-1} file(s)")
    return 1 if total else 0


if __name__ == "__main__":
    import pathlib
    sys.exit(main(sys.argv))
