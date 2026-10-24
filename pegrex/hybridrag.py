"""
hybridrag — pluggable embeddings

║  Embedder protocol: embed(text) -> dict[dim] -> float. The built-in     
║  HashEmbedder is fully local (char-n-gram feature hashing) -- zero      
║  dependencies, same shape as external sentence-embeddings. Retrieval    
║  fuses vector cosine with BM25; either alone is also available.         
║  The mini_llm n-gram mode stays as the offline fallback seam."""

from __future__ import annotations

import math
import re
from collections import Counter

_TOK = re.compile(r"[a-z0-9_]+")


def tokens(text):
    return _TOK.findall(text.lower())


class HashEmbedder:
    """Local char-n-gram feature hashing. Deterministic, zero-dep."""

    def __init__(self, dim=256, n=3):
        self.dim = dim
        self.n = n

    def embed(self, text):
        vec = Counter()
        t = " " + text.lower() + " "
        grams = [text.lower()] + [" ".join(tokens(text))]
        grams += [t[i:i + self.n] for i in range(len(t) - self.n + 1)]
        for g in grams:
            if not g.strip():
                continue # empty text -> empty vector
            h = hash(g) % self.dim
            vec[h] += 1.0
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        return {k: v / norm for k, v in vec.items()}


class BM25:
    """Classic BM25 over the tokenized corpus."""

    def __init__(self, docs, k1=1.5, b=0.75):
        self.k1, self.b = k1, b
        self.docs = [tokens(d) for d in docs]
        self.tf = [Counter(d) for d in self.docs]
        self.df = Counter()
        for d in self.docs:
            for t in set(d):
                self.df[t] += 1
        self.N = len(docs)
        self.avgdl = sum(len(d) for d in self.docs) / max(self.N, 1)

    def score(self, qi, d):
        dl = len(self.docs[d]) or 1
        tf = self.tf[d].get(qi, 0)
        if tf == 0:
            return 0.0
        idf = math.log(1 + (self.N - self.df.get(qi, 0) + 0.5) /
                       (self.df.get(qi, 0) + 0.5))
        return idf * tf * (self.k1 + 1) / (tf + self.k1 * (1 - self.b + self.b * dl / self.avgdl))

    def scores(self, query):
        qs = tokens(query)
        return [sum(self.score(qi, d) for qi in set(qs))
                for d in range(self.N)]


class HybridRetriever:
    """Fuse cosine(embedder) with BM25. Weights default 0.5/0.5."""

    def __init__(self, docs, embedder=None, w_vec=0.5, w_bm25=0.5):
        self.docs = list(docs)
        self.embedder = embedder or HashEmbedder()
        self.w_vec, self.w_bm25 = w_vec, w_bm25
        self.vecs = [self.embedder.embed(d) for d in self.docs]
        self.bm25 = BM25(docs)
        v = self.bm25.scores("x")   # touch to materialize
        mx = max((max(self.bm25.scores(" ".join(tokens(d)))) for d in self.docs), default=1.0)
        self._bm_scale = 1.0 / mx if mx else 1.0

    def _cos(self, a, b):
        dot = sum(v * b.get(k, 0.0) for k, v in a.items())
        return dot

    def search(self, query, k=3):
        qv = self.embedder.embed(query)
        bm = self.bm25.scores(query)
        scored = []
        for i, d in enumerate(self.docs):
            vec_s = self._cos(qv, self.vecs[i])
            bm_s = bm[i] * self._bm_scale
            fused = self.w_vec * vec_s + self.w_bm25 * bm_s
            scored.append((fused, i, vec_s, bm_s))
        scored.sort(key=lambda x: -x[0])
        return [{"doc": i, "score": round(s, 4), "vec": round(v, 4),
                 "bm25": round(b, 4)} for s, i, v, b in scored[:k]]


class NGramFallback:
    """The zero-dependency fallback seam: 
           n-gram overlap, same search API."""

    def __init__(self, docs, n=3):
        self.docs = list(docs)
        self.n = n

    def search(self, query, k=3):
        q = " ".join(tokens(query))
        scored = []
        for i, d in enumerate(self.docs):
            dd = " ".join(tokens(d))
            hit = sum(1 for j in range(len(q) - self.n + 1)
                      if q[j:j + self.n] in dd)
            scored.append((hit / max(len(q), 1), i))
        scored.sort(key=lambda x: -x[0])
        return [{"doc": i, "score": round(s, 4)} for s, i in scored[:k]]
