"""metaengine.py -- the meta-engine: from examples to an analysis system.
Orchestrates induction (grammar), rule mining (findings history), and the
frontend pattern (TagSpec from grammar shapes).  Every component exists; this is the conductor."""

from __future__ import annotations


def build_system(examples_pos: list, examples_neg: list, seed: str,
                   domain: str = "custom") -> dict:
    """Examples -> induced grammar -> inferred node tags -> rule skeletons."""
    from .induce import induce
    grammar, score = induce(examples_pos, examples_neg, seed)
    tags = sorted(set(__import__("re").findall(r"([A-Z][A-Za-z]+)\s*<-\s*[=|\-]?",
                                               grammar)))
    rules = [{"id": f"{domain}-rule-{i+1}", "severity": "MEDIUM",
              "message": f"mined pattern {t}",
              "match": {"kind": "file", "text": t, "confidence": "low"}}
             for i, t in enumerate(tags)]
    return {"grammar": grammar, "score": score, "tags": tags,
            "rule_skeletons": rules}
