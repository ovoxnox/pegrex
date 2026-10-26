from pegrex.interprocedural import summarize_source


SOURCE = '''
def helper(x):
    if x < 0:
        return 0
    return x + 1

def caller(x):
    print("calling")
    return helper(x)

def recurse(n):
    if n <= 0:
        return 0
    return recurse(n - 1)
'''


def test_interprocedural_pre_post_return_and_composition(tmp_path):
    report = summarize_source(SOURCE, path=str(tmp_path / "summaries.py"))
    helper = report["functions"]["helper"]
    assert helper["preconditions"]
    assert any(row["relation"] == "return == x + 1"
               for row in helper["postconditions"])
    caller = report["functions"]["caller"]
    assert any(row["relation"] == "return == (x + 1)" or
               row["relation"] == "return == x + 1"
               for row in caller["composed_postconditions"])
    assert any(row["category"] == "io" for row in caller["side_effects"])


def test_interprocedural_side_effects_are_inherited_with_provenance(tmp_path):
    source = '''def write(path):
    with open(path, "w") as stream:
        stream.write("x")

def caller(path):
    write(path)
    return 1
'''
    report = summarize_source(source, path=str(tmp_path / "effects.py"))
    effects = report["functions"]["caller"]["side_effects"]
    assert any(row["category"] == "filesystem" and row["origin"] == "inherited:write"
               for row in effects)


def test_recursion_is_explicit_unknown_not_unrolled_proof(tmp_path):
    report = summarize_source(SOURCE, path=str(tmp_path / "recursive.py"))
    recursive = report["functions"]["recurse"]
    assert recursive["composition_status"] == "unknown"
    assert any("fixpoint" in row for row in recursive["unknowns"])
    assert report["status"] == "unknown"


def test_summary_identity_is_content_defined(tmp_path):
    path = str(tmp_path / "same.py")
    first = summarize_source(SOURCE, path=path)
    second = summarize_source(SOURCE, path=path)
    assert first["summary_identity"] == second["summary_identity"]
    assert first["summary_identity"].startswith("sha256:")
