"""Grammar induction: examples in, lpegrex grammar out.
Fitness = compile_grammar as oracle (positives parse, negatives fail).
The mini LLM breaks ties toward DSL-plausible candidates."""
from __future__ import annotations

import random
import pathlib

from . import compile_grammar, peg


def fitness(text, positives, negatives):
    """fitness(text, positives, negatives): see module docstring."""
    try:
        start, rules = compile_grammar(text)
    except Exception:
        return (-1, -1)
    pos = sum(1 for s in positives if peg.run(start, s, rules)[1] is None)
    neg = sum(1 for s in negatives if peg.run(start, s, rules)[1] is not None)
    return (pos, neg)


def mutate(text, positive):
    """Example-driven mutations on the IR-as-text: inject a literal branch,
    widen the catch-all, adjust the entry rule's seed token."""
    toks = [t for t in positive.replace("(", " ").replace(")", " ").split() if t]
    ops = []
    if toks:
        lit = toks[0]
        ops.append(lambda t: t.replace("START <- .+", f"START <- '{lit}' / .+"))
    ops.append(lambda t: t.replace("CHAR <- [a-z]", "CHAR <- [a-z0-9]"))
    # restrictive: require the MLIR value prefix (rejects non-op lines)
    if ".+" in text:
        ops.append(lambda t: t.replace("START <- .+",
                                       "START <- '%' .+",
                                       1))
    return random.choice(ops)(text) if ops else text


def induce(positives, negatives, seed, rounds=60, seed_lm=42):
    """induce(positives, negatives, seed, rounds, seed_lm): see module docstring."""
    from .mini_llm import NGramLM
    random.seed(seed_lm)
    corpus = " ".join(p.read_text()
                      for p in pathlib.Path(__file__).parent.parent
                      .joinpath("examples").glob("*.gram"))
    lm = NGramLM(n=2)
    lm.train(corpus)
    best, score = seed, fitness(seed, positives, negatives)
    for _ in range(rounds):
        cand = mutate(best, random.choice(positives))
        if cand == best:
            continue
        s = fitness(cand, positives, negatives)
        if (s[0] > score[0]
                or (s[0] == score[0]
                    and (s[1] > score[1]
                         or (s[1] == score[1]
                             and lm.perplexity(cand)
                             < lm.perplexity(best))))):
            best, score = cand, s
        if score == (len(positives), len(negatives)):
            break
    return best, score
