from pegrex.incremental import IncrementalContractExtractor
from pegrex.sessions import AnalysisSession


SOURCE = '''
def helper(x):
    if x < 0:
        return 0
    return x

def caller(x):
    return helper(x)

def unrelated(x):
    return x + 1
'''


def test_function_change_reanalyzes_only_changed_body_and_callers(tmp_path):
    extractor = IncrementalContractExtractor()
    path = str(tmp_path / "module.py")
    first = extractor.update(path, SOURCE)
    assert len(first["analyzed"]) == 3
    unchanged = extractor.update(path, SOURCE)
    assert unchanged["analyzed"] == []
    changed_source = SOURCE.replace("return x\n\ndef caller", "return x + 2\n\ndef caller")
    update = extractor.update(path, changed_source)
    assert update["analyzed"] == [f"{path}::caller", f"{path}::helper"]
    assert update["reused"] == [f"{path}::unrelated"]
    assert any(row["outcome"] == "x + 2"
               for row in extractor.get(path, "helper")["contracts"])


def test_removed_callee_invalidates_existing_caller(tmp_path):
    extractor = IncrementalContractExtractor()
    path = str(tmp_path / "module.py")
    extractor.update(path, SOURCE)
    without_helper = SOURCE.replace('''def helper(x):
    if x < 0:
        return 0
    return x

''', "")
    update = extractor.update(path, without_helper)
    assert f"{path}::helper" in update["removed"]
    assert f"{path}::caller" in update["analyzed"]


def test_module_context_change_conservatively_invalidates_functions(tmp_path):
    extractor = IncrementalContractExtractor()
    path = str(tmp_path / "module.py")
    extractor.update(path, "LIMIT = 1\n" + SOURCE)
    update = extractor.update(path, "LIMIT = 2\n" + SOURCE)
    assert len(update["analyzed"]) == 3


def test_shared_ast_cache_uses_content_parser_and_configuration_identity():
    shared = {}
    source = "def f(x):\n    return x + 1\n"
    first = AnalysisSession(source, tree_cache=shared)
    second = AnalysisSession(source, path="different-name.py", tree_cache=shared)
    assert first.tree is second.tree
    other = AnalysisSession(source + "\n", tree_cache=shared)
    assert other.tree is not first.tree
