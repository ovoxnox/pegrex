"""
tokenizer

║  Dependency-free tokenizer with INDENT/DEDENT tracking — the lexer 
║  front-end a grammar compiler needs for layout-sensitive languages. 
║  Feeds token streams to grammars or straight into the mini LLM."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterator


@dataclass(frozen=True)
class Token:
    # NAME / NUMBER / STRING / OP / 
    # KEYWORD / INDENT / DEDENT / NEWLINE / EOF
    kind: str
    value: str
    line: int
    col: int


KEYWORDS = {"def", "if", "else", "elif", "while", "for", "in", "return", "import",
            "from", "class", "try", "except", "finally", "with", "as", "pass",
            "break", "continue", "and", "or", "not", "lambda", "None", "True", "False"}

_MULTI_OPS = ("==", "!=", "<=", ">=", "->", "+=", "-=", "*=", "//", "**")
_SINGLE_OPS = set("+-*/%=<>()[]{},:.;@")


def tokenize(src: str) -> list[Token]:
    """Python-ish token stream with INDENT/DEDENT events."""
    tokens: list[Token] = []
    indent_stack = [0]
    lines = src.splitlines()
    for lineno, raw in enumerate(lines, 1):
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())
        if indent > indent_stack[-1]:
            indent_stack.append(indent)
            tokens.append(Token("INDENT", "", lineno, indent + 1))
        while indent < indent_stack[-1]:
            indent_stack.pop()
            tokens.append(Token("DEDENT", "", lineno, indent + 1))
        col0 = indent + 1
        i, n = indent, len(raw)
        while i < n:
            c = raw[i]
            if c in " 	":
                i += 1
                continue
            if c == "#":
                break
            col = i + 1
            if c in "'\"":
                j = i + 1
                while j < n and raw[j] != c:
                    j += 1
                tokens.append(Token("STRING", raw[i:j + 1], lineno, col))
                i = j + 1
            elif c.isdigit():
                j = i
                while j < n and (raw[j].isalnum() or raw[j] in ".xX_"):
                    j += 1
                tokens.append(Token("NUMBER", raw[i:j], lineno, col))
                i = j
            elif c.isalpha() or c == "_":
                j = i
                while j < n and (raw[j].isalnum() or raw[j] == "_"):
                    j += 1
                word = raw[i:j]
                kind = "KEYWORD" if word in KEYWORDS else "NAME"
                tokens.append(Token(kind, word, lineno, col))
                i = j
            else:
                two = raw[i:i + 2]
                if two in _MULTI_OPS:
                    tokens.append(Token("OP", two, lineno, col))
                    i += 2
                elif c in _SINGLE_OPS:
                    tokens.append(Token("OP", c, lineno, col))
                    i += 1
                else:
                    i += 1
        if stripped and stripped[-1] not in '\"{[(':
            tokens.append(Token("NEWLINE", "", lineno, len(raw) + 1))
    lineno = len(lines)
    while len(indent_stack) > 1:
        indent_stack.pop()
        tokens.append(Token("DEDENT", "", lineno, 1))
    tokens.append(Token("EOF", "", lineno + 1, 1))
    return tokens


def token_stream(src: str) -> str:
    """Token kinds as a space-separated string — n-gram food for the mini LLM."""
    return " ".join(t.kind for t in tokenize(src))
