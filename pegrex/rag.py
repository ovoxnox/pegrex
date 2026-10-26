"""
rag

║  Retrieval-augmented generation: chunk sources (function-aware,          
║  file/line-addressed) into an index, then retrieve(query, k) via         
║  hybridrag.HybridRetriever (hybrid BM25 + local embeddings) --     
║  promoted into this served path rather than this module's own weaker    
║  BM25-lite-only scoring. Feeds the ACP server with grounded context      
║  (no external vector DB)."""

from __future__ import annotations

import pathlib
from dataclasses import dataclass, field

from .tokenizer import tokenize


@dataclass
class Chunk:
    source: str
    start_line: int
    text: str
    tokens: list = field(default_factory=list)


@dataclass
class Index:
    chunks: list = field(default_factory=list)
    inverted: dict = field(default_factory=dict)   # token -> set(chunk_idx)
    doc_len: list = field(default_factory=list)


def chunk_source(path: str, src: str, max_lines: int = 40) -> list[Chunk]:
    """Function-aware chunking (tree-sitter when available) else line windows."""
    chunks = []
    try:
        import pipeline
        parse, _, _ = pipeline.python_frontend()
        body = parse(src)
        lines = src.splitlines()
        for b in getattr(body, "children", []):
            if getattr(b, "tag", "") in ("function_definition", "async_function_definition"):
                start = src[:b.pos].count("\n") + 1
                end = src[:b.endpos].count("\n") + 1
                text = "\n".join(lines[start - 1:end])
                chunks.append(Chunk(path, start, text, []))
    except Exception:
        pass
    if not chunks:
        lines = src.splitlines()
        for i in range(0, len(lines), max_lines):
            chunks.append(Chunk(path, i + 1,
                                "\n".join(lines[i:i + max_lines]), []))
    for c in chunks:
        c.tokens = [(t.kind, t.value) for t in tokenize(c.text)]
    return chunks


def build_index(paths) -> Index:
    """Implement build index with the module's explicit API and failure semantics."""
    idx = Index()
    for p in paths:
        p = pathlib.Path(p)
        if p.is_dir():
            for f in sorted(p.rglob("*.py")):
                if "__pycache__" not in str(f) and ".vendor" not in str(f):
                    idx.chunks += chunk_source(str(f), f.read_text(encoding="utf-8"))
        elif p.exists():
            idx.chunks += chunk_source(str(p), p.read_text(encoding="utf-8"))
    for i, c in enumerate(idx.chunks):
        for tok in set(c.tokens):
            idx.inverted.setdefault(tok, set()).add(i)
    idx.doc_len = [len(c.tokens) for c in idx.chunks]
    return idx


def retrieve(idx: Index, query: str, k: int = 5) -> list[Chunk]:
    """Hybrid BM25 + local embeddings (HybridRetriever) over this
    index's chunk texts -- the chunking/indexing above stays this module's
    own (function-aware, file/line-addressed); only the scoring step was
    promoted from this module's BM25-lite-over-tagged-tokens to the
    stronger hybrid retriever, so served callers (api.py, acp.py) get it
    with no change to their own call sites."""
    from .hybridrag import HybridRetriever
    if not idx.chunks:
        return []
    docs = [c.text for c in idx.chunks]
    hits = HybridRetriever(docs).search(query, k=k)
    return [idx.chunks[h["doc"]] for h in hits]
