"""lpegc.compiler - the LPeg grammar-text compiler core."""

from __future__ import annotations

import re
from typing import Any, Callable

from .. import peg
from ..peg import (AndP, AltP, AnyP, BackP, CapP, CmtP, CpP, CsP, CtP, Eps,
                  EqBackP, FoldP, FuncP, GroupP, Lit, NodeP, NotP, RepP,
                  SeqP, SetP, ThrowP, ValP, V)

NL = chr(10)



from .diagnostics import GrammarError, _Expected, _NoPattern
from .parser import (PRELUDE, _NAME_START, _NAME_CONT, _PUNCT,
                     _kids, _tochar, _toutf8char, _tonumber,
                     _toemptytable, _foldleft, _foldright,
                     _rfoldleft, _rfoldright)

DEFAULT_OPTIONS = {
    "tag": "tag", "pos": "pos", "endpos": "endpos",
    "SKIP": "SKIP", "NAME_SUFFIX": "NAME_SUFFIX",
}

class GrammarCompiler:
    """One grammar text -> (start pattern, rules dict).  Cursor-driven."""

    def __init__(self, defs: dict | None = None, options: dict | None = None) -> None:
        self.defs = dict(defs or {})
        self.options = DEFAULT_OPTIONS | (options or {})
        self.rules: dict[str, peg.Patt] = {}
        self.order: list[str] = []
        self.first: str | None = None
        self.tokens: list[str] = []
        self.keywords: list[str] = []
        self.redefining: set[str] = set()
        self.text = ""
        self.i = 0

    # ── cursor
    def skip(self) -> None:
        """Implement skip with the module's explicit API and failure semantics."""
        s, i, n = self.text, self.i, len(self.text)
        while i < n:
            if s[i] in " \t\n\r\f\v":
                i += 1
            elif s.startswith("--", i):
                j = s.find(NL, i)
                i = n if j < 0 else j + 1
            else:
                break
        self.i = i

    def at(self, lit: str) -> bool:
        """Implement at with the module's explicit API and failure semantics."""
        return self.text.startswith(lit, self.i)

    def eat(self, lit: str) -> bool:
        """Implement eat with the module's explicit API and failure semantics."""
        if self.at(lit):
            self.i += len(lit)
            return True
        return False

    def need(self, lit: str, msg: str) -> None:
        """Implement need with the module's explicit API and failure semantics."""
        if not self.eat(lit):
            raise _Expected(msg, self.text, self.i)

    def eof(self) -> bool:
        """Implement eof with the module's explicit API and failure semantics."""
        self.skip()
        return self.i >= len(self.text)

    def name(self) -> str:
        """Implement name with the module's explicit API and failure semantics."""
        self.skip()
        s = self.text
        if self.i >= len(s) or s[self.i] not in _NAME_START:
            raise _Expected("expected a name", s, self.i)
        j = self.i + 1
        while j < len(s) and s[j] in _NAME_CONT:
            j += 1
        while j < len(s) and s[j] == "-" and j + 1 < len(s) and s[j + 1] in _NAME_CONT:
            j += 1
            while j < len(s) and s[j] in _NAME_CONT:
                j += 1
        nm = s[self.i:j]
        self.i = j
        return nm

    def string(self) -> str:
        """Implement string with the module's explicit API and failure semantics."""
        self.skip()
        s = self.text
        if self.i >= len(s) or s[self.i] not in "'\"":
            raise _Expected("expected a string", s, self.i)
        q = s[self.i]
        j = s.find(q, self.i + 1)
        if j < 0:
            raise _Expected("missing terminating quote", s, self.i)
        out = s[self.i + 1:j]
        self.i = j + 1
        return out

    def number(self) -> int:
        """Implement number with the module's explicit API and failure semantics."""
        self.skip()
        s, i = self.text, self.i
        j = i + (s[i] in "+-")
        while j < len(s) and s[j].isdigit():
            j += 1
        if j == i or not s[i:j].lstrip("+-").isdigit():
            raise _Expected("expected a number", s, i)
        self.i = j
        return int(s[i:j])

    def userdef(self, nm: str):
        """Implement userdef with the module's explicit API and failure semantics."""
        if nm in self.defs:
            return self.defs[nm]
        if nm in PRELUDE and PRELUDE[nm] is not None:
            return PRELUDE[nm]
        if len(nm) == 1 and nm.isupper() and nm.lower() in PRELUDE:
            inner = PRELUDE[nm.lower()]
            return NotP(inner) if isinstance(inner, SetP) else None
        raise GrammarError(f"name '{nm}' undefined")

    # ── entry
    def compile(self, text: str):
        """Implement compile with the module's explicit API and failure semantics."""
        self.text, self.i = text, 0
        while not self.eof():
            self.definition()
        if self.first is None:
            raise GrammarError("empty grammar")
        self.finalize_tokens()
        return self.rules[self.first]

    def add_rule(self, nm: str, p: peg.Patt) -> None:
        """Implement add rule with the module's explicit API and failure semantics."""
        if nm in self.rules:
            raise GrammarError(f"'{nm}' already defined as a rule")
        self.rules[nm] = p
        self.order.append(nm)
        if self.first is None:
            self.first = nm

    def definition(self) -> None:
        """Implement definition with the module's explicit API and failure semantics."""
        self.skip()
        start = self.i
        if self.at("`"): # token/keyword redefinition rule
            self.i += 1
            j = self.text.find("`", self.i)
            word = self.text[self.i:j]
            self.i = j + 1
            self.skip()
            if not (self.eat("<--") or self.eat("<-")):
                raise _Expected("expected rule arrow after token name",
                                self.text, start)
            self.redefining.add(word) # inner refs freeze as literals
            try:
                p = self.expression()
            finally:
                self.redefining.discard(word)
            self.rules[word] = p
            self.rules["\0TOKEN:" + word] = p
            return
        nm = self.name()
        self.skip()
        tag = None
        save = self.i
        if self.eat(":"):
            tag = self.name()
            self.skip()
        if self.eat("<=="):
            self.add_rule(nm, NodeP(tag or nm, self.expression()))
        elif tag is not None:
            raise _Expected("expected '<==' after tagged rule name",
                            self.text, self.i)
        elif self.eat("<-|"):
            self.add_rule(nm, CtP(self.expression()))
        elif self.eat("<--") or self.eat("<-"):
            self.add_rule(nm, self.expression())
        else:
            raise _Expected("expected rule arrow ('<==', '<-|', '<--')",
                            self.text, start)

    # ── expressions
    def at_rule_start(self) -> bool:
        """Implement at rule start with the module's explicit API and failure semantics."""
        save = self.i
        try:
            if self.at("`"):
                self.i += 1
                j = self.text.find("`", self.i)
                if j < 0:
                    return False
                self.i = j + 1
                self.skip()
                return (self.at("<==") or self.at("<-|")
                        or self.at("<--") or self.at("<-"))
            self.name()
            self.skip()
            if self.at(":"):
                self.i += 1
                self.name()
                self.skip()
            return (self.at("<==") or self.at("<-|")
                    or self.at("<--") or self.at("<-"))
        except _Expected:
            return False
        finally:
            self.i = save

    def expression(self):
        """Implement expression with the module's explicit API and failure semantics."""
        p = self.sequence()
        self.skip()
        while self.eat("/"):
            p = AltP(p, self.sequence())
            self.skip()
        return p

    def sequence(self):
        """Implement sequence with the module's explicit API and failure semantics."""
        ps = []
        self.skip()
        while (not self.eof() and not self.at("/") and not self.at(")")
               and not self.at_rule_start()):
            try:
                ps.append(self.prefixed())
            except _NoPattern:
                break # PEG semantics: a non-pattern ends the sequence
            self.skip()
        if not ps:
            return Eps()
        return ps[0] if len(ps) == 1 else SeqP(*ps)

    def prefixed(self):
        """Implement prefixed with the module's explicit API and failure semantics."""
        self.skip()
        if self.eat("&"):
            return AndP(self.prefixed())
        if self.eat("!"):
            return NotP(self.prefixed())
        return self.suffixed()

    def suffixed(self):
        """Implement suffixed with the module's explicit API and failure semantics."""
        p = self.primary()
        while True:
            self.skip()
            if self.eat("~?"):
                p = AltP(p, SeqP(Eps(), ValP(False)))
            elif self.eat("+"):
                p = RepP(p, 1, None)
            elif self.eat("*"):
                p = RepP(p, 0, None)
            elif self.eat("?"):
                p = RepP(p, 0, 1)
            elif self.eat("^"):
                self.skip()
                s = self.text
                if self.i < len(s) and (s[self.i].isdigit() or s[self.i] in "+-"):
                    if s[self.i] in "+-":
                        sign = s[self.i]
                        self.i += 1
                        n = self.number()
                        # re semantics: ^+n at least n, ^-n up to n
                        p = RepP(p, n, None) if sign == "+" else RepP(p, 0, n)
                    else:
                        p = RepP(p, (n := self.number()), n)   # ^n exactly n
                else:
                    p = AltP(p, ThrowP(self.name()))            # ^Label
            elif self.at("->"):
                self.i += 2
                self.skip()
                if self.eat("{}"):
                    p = CtP(p)
                elif (self.i < len(self.text) and
                      (self.text[self.i].isdigit() or
                       (self.text[self.i] in "+-" and self.i + 1 < len(self.text)
                        and self.text[self.i + 1].isdigit()))):
                    v = self.number()
                    p = FuncP(p, (lambda x: lambda *_: x)(v))
                else:
                    target = (self.string() if self.at("'") or self.at('"')
                              else self.name())
                    fn = self._as_fn(target)
                    p = FuncP(p, fn)
            elif self.at("=>"):
                self.i += 2
                fn = self.userdef(self.name())
                if not callable(fn):
                    raise GrammarError(f"'{fn}' is not a match-time function")
                p = CmtP(p, fn)
            elif self.at("~>"):
                self.i += 2
                fn = self.userdef(self.name())
                if not callable(fn):
                    raise GrammarError(f"'{fn}' is not a fold function")
                p = FoldP(p, fn)
            else:
                break
        return p

    def _as_fn(self, target):
        if callable(self.defs.get(target)):
            return self.defs[target]
        if callable(PRELUDE.get(target)):
            return PRELUDE[target]
        v = int(target) if target.lstrip("+-").isdigit() else target
        return (lambda x: lambda *_: x)(v)

    # ── primaries
    def primary(self):
        """Implement primary with the module's explicit API and failure semantics."""
        self.skip()
        s = self.text
        if self.i >= len(s):
            raise _Expected("expected a pattern", s, self.i)
        c = s[self.i]
        if c == "(":
            self.i += 1
            p = self.expression()
            self.skip()
            self.need(")", "missing closing ')'")
            return p
        if c in "'\"":
            return Lit(self.string())
        if c == "`":
            return self.backtick(capture=False)
        if c == "[":
            return self.clazz()
        if c == ".":
            self.i += 1
            return AnyP()
        if c == "$":
            return self.dollar()
        if c == "@":
            self.i += 1
            return self.expected()
        if c == "{":
            return self.brace()
        if c == "%":
            self.i += 1
            self.skip()
            if self.eat("{"):
                lbl = self.name()
                self.skip()
                self.need("}", "missing closing '}'")
                return ThrowP(lbl)
            nm = self.name()
            d = self.userdef(nm)
            if isinstance(d, peg.Patt):
                return d
            raise GrammarError(f"'{nm}' is a function, not a pattern")
        if c == "=":
            self.i += 1
            return EqBackP(self.name())
        if c in _NAME_START:
            return V(self.name())
        raise _NoPattern(f"unexpected character {c!r}", s, self.i)

    def expected(self):
        """Implement expected with the module's explicit API and failure semantics."""
        self.skip()
        s = self.text
        if self.i < len(s) and s[self.i] in "'\"":
            lit = self.string()
            return AltP(Lit(lit), ThrowP("Expected_" + lit))
        if self.i < len(s) and s[self.i] == "`":
            p = self.backtick(capture=False)
            lbl = "Expected_" + self._last_tick
        else:
            nm = self.name()
            p = V(nm)
            lbl = "Expected_" + nm
        return AltP(p, ThrowP(lbl))

    _last_tick = ""

    def backtick(self, capture: bool):
        """Implement backtick with the module's explicit API and failure semantics."""
        s = self.text
        j = s.find("`", self.i + 1)
        if j < 0:
            raise _Expected("missing terminating backtick", s, self.i)
        word = s[self.i + 1:j]
        self.i = j + 1
        self._last_tick = word
        if not word:
            raise _Expected("expected a keyword or token after '`'", s, self.i)
        if word[0] in _NAME_START:
            p = self.make_keyword(word)
        elif all(ch in _PUNCT and ch != "_" for ch in word):
            p = self.make_token(word)
        else:
            raise _Expected("invalid keyword/token", s, self.i)
        return SeqP(p, ValP(word)) if capture else p

    def make_keyword(self, kw: str):
        """Implement make keyword with the module's explicit API and failure semantics."""
        if kw not in self.keywords:
            self.keywords.append(kw)
        return SeqP(Lit(kw), NotP(V(self.options["NAME_SUFFIX"])),
                    V(self.options["SKIP"]))

    def make_token(self, tok: str):
        """Implement make token with the module's explicit API and failure semantics."""
        if tok not in self.tokens:
            self.tokens.append(tok)
        if tok in self.redefining: # freeze original literal inside a redefine
            return SeqP(Lit(tok), V(self.options["SKIP"]))
        return SeqP(V("\0TOKEN:" + tok), V(self.options["SKIP"]))

    def clazz(self):
        """Implement clazz with the module's explicit API and failure semantics."""
        self.need("[", "expected '['")
        complement = self.eat("^")
        items = []
        while True:
            self.skip()
            if self.eat("]"):
                break
            if self.i >= len(self.text):
                raise _Expected("missing closing ']'", self.text, self.i)
            first = self.class_item()
            if isinstance(first, peg.Patt):
                items.extend(first.items)
                continue
            save = self.i
            self.skip()
            if self.at("-") and self.text[self.i + 1] != "]":
                self.i += 1
                self.skip()
                last = self.class_item()
                if isinstance(last, peg.Patt):
                    raise _Expected("bad range", self.text, save)
                items.append((min(first, last), max(first, last)))
            else:
                items.append(first)
        return SetP(items, complement)

    def class_item(self):
        """Implement class item with the module's explicit API and failure semantics."""
        s = self.text
        c = s[self.i]
        if c == "%":
            self.i += 1
            nm = self.name()
            d = self.userdef(nm)
            if isinstance(d, SetP):
                return d
            if isinstance(d, Lit) and len(d.text) == 1:
                return d.text
            raise GrammarError(f"'%{nm}' not usable inside a class")
        self.i += 1
        return c

    def dollar(self):
        """Implement dollar with the module's explicit API and failure semantics."""
        self.i += 1
        s = self.text
        for lit, val in (("nil", None), ("true", True), ("false", False)):
            if self.at(lit):
                self.i += len(lit)
                return ValP(val)
        if self.eat("{}"):
            return ValP([])
        c = s[self.i] if self.i < len(s) else ""
        if c in "+-" or c.isdigit():
            save = self.i
            try:
                return ValP(self.number())
            except _Expected:
                self.i = save
        if c in "'\"":
            return ValP(self.string())
        return ValP(self.userdef(self.name()))

    def brace(self):
        """Implement brace with the module's explicit API and failure semantics."""
        self.i += 1
        self.skip()
        if self.at("`"): # `{`tok`}` capture — only when `}` follows
            save = self.i
            p = self.backtick(capture=True)
            self.skip()
            if self.eat("}"):
                return p
            self.i = save # else: plain group starting with a token
        if self.eat("~"):
            p = self.expression()
            self.skip()
            self.need("~}", "missing closing '~}'")
            return CsP(p)
        if self.eat("|"):
            p = self.expression()
            self.skip()
            self.need("|}", "missing closing '|}'")
            return CtP(p)
        if self.eat(":"):
            # named group — but `{:name patt :}` is anonymous unless name
            # is IMMEDIATELY followed by ':' (lpegrex: Name*":" + Cc(nil))
            save = self.i
            nm = None
            if self.i < len(self.text) and self.text[self.i] in _NAME_START:
                cand = self.name()
                if self.eat(":"):
                    nm = cand
                else:
                    self.i = save
            p = self.expression()
            self.skip()
            self.need(":}", "missing closing ':}'")
            return GroupP(nm, p)
        if self.eat("}"):
            return CpP()
        p = self.expression()
        self.skip()
        self.need("}", "missing closing '}'")
        return CapP(p)

    # ── finalize
    def finalize_tokens(self) -> None:
        """Implement finalize tokens with the module's explicit API and failure semantics."""
        skip = V(self.options["SKIP"])
        bases: dict[str, peg.Patt] = {}
        for tok in self.tokens: # unique-token exclusion among prefixes
            b: peg.Patt = Lit(tok)
            for other in self.tokens:
                if other != tok and other.startswith(tok):
                    b = SeqP(NotP(Lit(other)), b)
            bases[tok] = b
        for tok in self.tokens:
            key = "\0TOKEN:" + tok
            if key not in self.rules: # redefinition already installed it
                self.rules[key] = SeqP(bases[tok], skip)
        if self.tokens:
            self.rules["TOKEN"] = AltP(*(self.rules["\0TOKEN:" + t]
                                         for t in self.tokens))
        if self.keywords:
            self.rules["KEYWORD"] = AltP(*(self.make_keyword(k)
                                           for k in self.keywords))


def compile_grammar(text: str, defs: dict | None = None,
                    options: dict | None = None):
    """Compile grammar text -> (start pattern, rules dict)."""
    gc = GrammarCompiler(defs, options)
    start = gc.compile(text)
    return start, gc.rules


# ── diagnostics
def calcline(subject: str, position: int):
    """(lineno, colno, line text) at position — lpegrex.calcline."""
    position = max(0, min(position, len(subject)))
    lineno = subject.count(NL, 0, position) + 1
    linestart = subject.rfind(NL, 0, position) + 1
    lineend = subject.find(NL, position)
    lineend = len(subject) if lineend < 0 else lineend
    return lineno, position - linestart + 1, subject[linestart:lineend]


def prettyast(node, indent: str = "", out: list | None = None) -> str:
    """Render a Node tree, lpegrex.prettyast-style."""
    if out is None:
        out = []
    if isinstance(node, peg.Node):
        out.append(indent + (node.tag or "-"))
        indent += "| "
        for ch in node.children:
            prettyast(ch, indent, out)
    elif isinstance(node, str):
        esc = (node.replace("\\", "\\\\").replace('"', '\\"')
                    .replace(NL, "\\n").replace("\t", "\\t").replace("\r", "\\r"))
        out.append(indent + '"' + esc + '"')
    else:
        out.append(indent + repr(node))
    return NL.join(out)
