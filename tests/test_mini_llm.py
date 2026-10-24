import pathlib

from pegrex.mini_llm import NGramLM

CORPUS = (pathlib.Path(__file__).parent.parent / "specs" / "chain.py").read_text() \
    + (pathlib.Path(__file__).parent.parent / "specs" / "fact.py").read_text()


def test_train_generate_perplexity():
    lm = NGramLM(n=3)
    lm.train(CORPUS)
    out = lm.generate("def f", 15)
    kinds = out.split()
    assert len(kinds) == 19                 # seed KEYWORD NAME NEWLINE EOF + 15
    assert kinds[0] == "KEYWORD" and kinds[1] == "NAME"
    p = lm.perplexity(CORPUS[:200])
    assert p == p and p > 0                 # finite
