import pathlib
import sys
import tempfile

from pegrex.mini_llm import NGramLM  # noqa: F401  (vendoring side-effect)


def _run_sca(tmp, files):
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    from tools.mkspec.core import run_analyzers
    for name, text in files.items():
        (tmp / name).write_text(text)
    # the SCA analyzer inventories manifests adjacent to the ENTRY file;
    # pick a real source file as the entry (go.mod-only fixtures have none)
    entry = next((tmp / n for n in ("main.go", "main.rs", "main.py")
                  if (tmp / n).exists()), None)
    assert entry is not None, "fixture must contain a source entry file"
    ctx, facts = run_analyzers(str(entry), ["sca"])
    return facts


def test_go_mod_inventory():
    tmp = pathlib.Path(tempfile.mkdtemp())
    facts = _run_sca(tmp, {
        "go.mod": "module example.com/app\n\ngo 1.21\n\n"
                  "require github.com/foo/bar v1.2.3\n",
        "main.go": "package main\nfunc main() {}\n",
    })
    deps = [f.evidence for f in facts if f.check_id == "go-dependency"]
    assert any("github.com/foo/bar v1.2.3" in d for d in deps), deps


def test_cargo_lock_inventory():
    tmp = pathlib.Path(tempfile.mkdtemp())
    facts = _run_sca(tmp, {
        "Cargo.lock": '[[package]]\nname = "serde"\nversion = "1.0.0"\n',
        "main.rs": "fn main() {}\n",
    })
    deps = [f.evidence for f in facts if f.check_id == "crate-dependency"]
    assert any("serde v1.0.0" in d for d in deps), deps
