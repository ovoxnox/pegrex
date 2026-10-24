from pegrex.tokenizer import tokenize, token_stream


def test_indent_dedent():
    ts = tokenize("def f(n):\n    if n > 0:\n        return n\n    return -n\n")
    kinds = [t.kind for t in ts]
    assert kinds.count("INDENT") == 2, kinds
    assert kinds.count("DEDENT") == 2, kinds
    assert kinds[0] == "KEYWORD" and ts[0].value == "def"
    assert kinds[-1] == "EOF"


def test_token_stream_feeds_ngrams():
    s = token_stream("x = 1\ny = 2\n")
    assert "NAME OP NUMBER NEWLINE" in s
