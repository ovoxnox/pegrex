try:
    import pytest
except ImportError:
    class _Raises:
        def __init__(self, exc): self.exc = exc
        def __enter__(self): return self
        def __exit__(self, t, v, tb):
            assert t is not None and issubclass(t, self.exc), f"expected {self.exc}"
            return True
    class _PytestShim:
        @staticmethod
        def raises(exc): return _Raises(exc)
    pytest = _PytestShim()


from pegrex.hybridrag import BM25, HashEmbedder, HybridRetriever, NGramFallback

CORPUS = [
    "def absval(n): return n if n >= 0 else -n   # absolute value function",
    "def classify(n): return 1 if n > 0 else -1   # sign of a number",
    "def clamp(x, lo, hi): return max(lo, min(hi, x))   # bound a value",
    "def factorial(n): return 1 if n <= 1 else n * factorial(n - 1)",
]


def test_embedder_deterministic_normalized():
    emb = HashEmbedder()
    v1, v2 = emb.embed("absolute value"), emb.embed("absolute value")
    assert v1 == v2 and abs(sum(x * x for x in v1.values()) - 1.0) < 1e-6


def test_bm25_ranks_relevant_first():
    s = BM25(CORPUS).scores("absolute value function")
    assert s[0] > s[1] and s[0] > 0


def test_hybrid_hard_query():
    r = HybridRetriever(CORPUS).search("function that makes numbers positive", k=2)
    assert r[0]["doc"] == 0


def test_fallback_answers():
    assert NGramFallback(CORPUS).search("absolute value", k=2)[0]["doc"] == 0


def test_empty_text_empty_vector():
    v = HashEmbedder().embed("")
    assert v == {} or abs(sum(x * x for x in v.values())) < 1e-6
