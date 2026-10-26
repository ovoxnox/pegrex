import json
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


def test_offline_osv_missing_evidence_is_unknown_not_clean(tmp_path):
    from pegrex.sca import scan
    lockfile = tmp_path / "go.mod"
    lockfile.write_text("module example.com/app\n\nrequire github.com/foo/bar v1.2.3\n")
    report = scan(str(lockfile), offline=True, cache_path=tmp_path / "missing.json")
    assert report["offline"] is True
    assert report["status"] == "unknown"
    assert report["vulnerabilities"] == []
    assert len(report["unknowns"]) == 1
    assert report["provenance"]["osv"]["id"] == "unavailable"
    assert report["provenance"]["source"]["sha256"]


def test_requirements_inventory_offline_missing_evidence_is_unknown(tmp_path):
    from pegrex.sca import inventory_from, scan
    requirements = tmp_path / "requirements-ci.txt"
    requirements.write_text("# exact test environment\npydantic==2.11.4\nz3-solver==5.3.1.0\n")
    assert inventory_from(str(requirements)) == [
        {"name": "pydantic", "version": "2.11.4", "ecosystem": "PyPI"},
        {"name": "z3-solver", "version": "5.3.1.0", "ecosystem": "PyPI"},
    ]
    report = scan(str(requirements), offline=True,
                  cache_path=tmp_path / "missing.json")
    assert report["dependencies"] == 2
    assert report["status"] == "unknown"
    assert len(report["unknowns"]) == 2
    assert report["vulnerabilities"] == []


def test_unpinned_and_unsupported_inventory_never_looks_complete(tmp_path):
    from pegrex.sca import scan
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("pydantic>=2,<3\n")
    report = scan(str(requirements), offline=True,
                  cache_path=tmp_path / "missing.json")
    assert report["dependencies"] == 0 and report["status"] == "unknown"
    assert "unpinned" in report["unknowns"][0]["reason"]
    unsupported = tmp_path / "dependencies.txt"
    unsupported.write_text("pydantic==2.11.4\n")
    report = scan(str(unsupported), offline=True,
                  cache_path=tmp_path / "missing.json")
    assert report["status"] == "unknown"
    assert "unsupported dependency inventory" in report["unknowns"][0]["reason"]


def test_osv_snapshot_is_exact_reproducible_and_offline(tmp_path):
    from pegrex.sca import scan
    lockfile = tmp_path / "go.mod"
    lockfile.write_text("module example.com/app\n\nrequire github.com/foo/bar v1.2.3\n")
    dependency = {"name": "github.com/foo/bar", "version": "1.2.3",
                  "ecosystem": "Go"}
    snapshot = tmp_path / "osv-snapshot.json"
    snapshot.write_text(json.dumps({
        "schema": "pegrex.osv-snapshot.v1", "snapshot": "osv-test-2026-10-25",
        "queries": {"Go:github.com/foo/bar:1.2.3": {
            "dependency": dependency,
            "vulnerabilities": [{"id": "GO-TEST-001", "summary": "test vulnerability"}],
        }},
    }, indent=1))
    first = scan(str(lockfile), offline=True, snapshot=snapshot)
    second = scan(str(lockfile), offline=True, snapshot=snapshot)
    assert first == second
    assert first["status"] == "complete"
    assert [v["id"] for v in first["vulnerabilities"]] == ["GO-TEST-001"]
    assert first["provenance"]["osv"]["id"] == "osv-test-2026-10-25"
    assert first["provenance"]["osv"]["reproducible"] is True
    assert len(first["provenance"]["osv"]["sha256"]) == 64


def test_osv_snapshot_missing_dependency_is_unknown(tmp_path):
    from pegrex.sca import scan
    lockfile = tmp_path / "go.mod"
    lockfile.write_text("module example.com/app\n\nrequire github.com/foo/bar v1.2.3\n")
    snapshot = tmp_path / "osv-snapshot.json"
    snapshot.write_text('{"schema":"pegrex.osv-snapshot.v1","snapshot":"empty","queries":{}}')
    report = scan(str(lockfile), snapshot=snapshot)
    assert report["offline"] is True and report["status"] == "unknown"
    assert report["vulnerabilities"] == [] and report["unknowns"]
