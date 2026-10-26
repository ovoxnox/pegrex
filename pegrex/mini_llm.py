"""
mini_llm

║  A smoothed n-gram language model over the tokenizer's token streams.    
║  Educational scale — same math as the first LMs. Deterministic (argmax)."""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field

from .tokenizer import token_stream


@dataclass
class NGramLM:
    """NGramLM - see module docstring."""
    n: int = 3
    alpha: float = 0.4
    counts: dict = field(default_factory=dict)
    vocab: set = field(default_factory=set)

    def _ctx(self, toks, i):
        return tuple(toks[max(0, i - self.n + 1):i]) or ("<s>",)

    def train(self, text: str) -> None:
        """Implement train with the module's explicit API and failure semantics."""
        toks = token_stream(text).split()
        self.vocab |= set(toks)
        for i, t in enumerate(toks):
            self.counts.setdefault(self._ctx(toks, i), Counter())[t] += 1

    def next(self, ctx: list[str]) -> str:
        """Implement next with the module's explicit API and failure semantics."""
        c = self.counts.get(tuple(ctx[-(self.n - 1):]) or ("<s>",), Counter())
        if not c:
            totals = Counter()
            for cnt in self.counts.values():
                totals.update(cnt)
            return totals.most_common(1)[0][0]
        total = sum(c.values()) + self.alpha * len(self.vocab)
        return max(self.vocab, key=lambda v: (c[v] + self.alpha) / total)

    def generate(self, seed: str, length: int = 20) -> str:
        """Implement generate with the module's explicit API and failure semantics."""
        toks = token_stream(seed).split() or ["<s>"]
        for _ in range(length):
            toks.append(self.next(toks))
        return " ".join(toks)

    def perplexity(self, text: str) -> float:
        """Implement perplexity with the module's explicit API and failure semantics."""
        toks, logp, m = token_stream(text).split(), 0.0, 0
        for i, t in enumerate(toks):
            c = self.counts.get(self._ctx(toks, i), Counter())
            total = sum(c.values()) + self.alpha * len(self.vocab)
            logp += math.log((c[t] + self.alpha) / total)
            m += 1
        return math.exp(-logp / max(m, 1))
