import base64, json
from pathlib import Path
import pytest

from pegrex.buildprovenance import create_build_provenance, verify_build_provenance
from pegrex.lockpolicy import check_lockfile_policy
from pegrex.reachability import scan_reachable
from pegrex.sbom import generate_sbom


def _lock(path, demo=True):
    integrity = "sha256-" + base64.b64encode(bytes(range(32))).decode()
    data = {"lockfileVersion": 3, "packages": {"": {"dependencies": {"demo": "1.0.0"}},
        "node_modules/demo": {"version": "1.0.0", "resolved": "https://registry.invalid/demo.tgz",
                              "integrity": integrity}}}
    path.write_text(json.dumps(data))
    return data


def test_reachability_distinguishes_installed_reachable_and_unobserved(tmp_path):
    lock = tmp_path / "package-lock.json"; _lock(lock)
    snapshot = tmp_path / "osv.json"
    snapshot.write_text(json.dumps({"queries": {"npm:demo:1.0.0": {"vulnerabilities": [
        {"id": "VULN-1", "affected_functions": ["demo.evil"]}]}}}))
    (tmp_path / "app.py").write_text("""import demo
demo.evil()
""")
    result = scan_reachable(lock, tmp_path, snapshot=snapshot)
    assert result["findings"][0]["installed"] is True
    assert result["findings"][0]["reachability"] == "reachable"
    assert result["findings"][0]["call_sites"][0]["line"] == 2
    (tmp_path / "app.py").write_text("""value = 1
""")
    unobserved = scan_reachable(lock, tmp_path, snapshot=snapshot)
    assert unobserved["findings"][0]["reachability"] == "not-observed"
    assert unobserved["findings"][0]["installed"] is True


def test_missing_vulnerable_symbols_and_parse_coverage_are_unknown(tmp_path):
    lock = tmp_path / "package-lock.json"; _lock(lock)
    snapshot = tmp_path / "osv.json"
    snapshot.write_text(json.dumps({"queries": {"npm:demo:1.0.0": []}}))
    # Add a vulnerability without symbols through a second snapshot.
    snapshot.write_text(json.dumps({"queries": {"npm:demo:1.0.0": [{"id": "VULN-2"}]}}))
    (tmp_path / "app.py").write_text("""import demo
""")
    result = scan_reachable(lock, tmp_path, snapshot=snapshot)
    assert result["findings"][0]["reachability"] == "unknown"
    assert result["verdict"] == "unknown"


def test_cyclonedx_and_spdx_include_graph_hashes_licenses_and_provenance(tmp_path):
    lock = tmp_path / "package-lock.json"; data = _lock(lock)
    data["packages"]["node_modules/demo"]["dependencies"] = {"child": "2.0.0"}
    data["packages"]["node_modules/child"] = {"version": "2.0.0", "integrity": "sha256-" + base64.b64encode(b"x" * 32).decode()}
    lock.write_text(json.dumps(data))
    cdx = generate_sbom(lock, licenses={"demo": "MIT"})
    assert cdx["bomFormat"] == "CycloneDX" and len(cdx["components"]) == 2
    assert cdx["components"][0]["hashes"]
    assert any(row["dependsOn"] for row in cdx["dependencies"])
    assert any("child: license NOASSERTION" == row["value"] for row in cdx["metadata"]["properties"] if row["name"] == "pegrex:unknown")
    spdx = generate_sbom(lock, format="spdx", licenses={"demo": "MIT", "child": "Apache-2.0"})
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert any(row["relationshipType"] == "DEPENDS_ON" for row in spdx["relationships"])
    assert "provenance" in spdx["documentComment"]


def test_requirements_sbom_is_offline_versioned_and_fail_closed(tmp_path):
    requirements = tmp_path / "requirements-ci.txt"
    requirements.write_text("pydantic==2.11.4\nz3-solver==5.3.1.0\n")
    cdx = generate_sbom(requirements)
    assert [row["purl"] for row in cdx["components"]] == [
        "pkg:pypi/pydantic@2.11.4", "pkg:pypi/z3-solver@5.3.1.0"]
    tool = cdx["metadata"]["tools"]["components"][0]
    assert tool["version"] == "1.3.0"
    unknowns = [row["value"] for row in cdx["metadata"]["properties"]
                if row["name"] == "pegrex:unknown"]
    assert "pydantic: integrity hash missing" in unknowns
    spdx = generate_sbom(requirements, format="spdx")
    assert spdx["creationInfo"]["creators"] == ["Tool: PegRex-1.3.0"]


def test_lockfile_policy_violations_and_typosquat_signals(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("""numpy>=1.0
demo @ http://example.invalid/a.whl
reqeusts==2.31.0
""")
    result = check_lockfile_policy(requirements)
    rules = {row["rule_id"] for row in result["violations"]}
    assert {"unpinned-dependency", "unsafe-url-dependency", "unhashed-url-dependency"} <= rules
    assert result["typosquatting_signals"][0]["package"] == "reqeusts"
    assert result["verdict"] == "refuted"
    requirements.write_text("""demo @ git+https://example.invalid/repo.git@main
""")
    assert "unpinned-vcs-reference" in {row["rule_id"] for row in check_lockfile_policy(requirements)["violations"]}


def test_build_provenance_binds_subjects_and_materials_and_detects_tampering(tmp_path):
    artifact = tmp_path / "app.py"; artifact.write_text("""print('ok')
""")
    material = tmp_path / "source.py"; material.write_text("""print('ok')
""")
    statement = create_build_provenance({"app.py": artifact}, builder_id="local-test",
        command_argv=["python", "-m", "py_compile", "app.py"], build_type="test-build",
        materials={"source.py": material})
    assert statement["_type"] == "https://in-toto.io/Statement/v1"
    assert statement["subject"][0]["digest"]["sha256"]
    verified = verify_build_provenance(statement, subject_paths={"app.py": artifact},
                                       material_paths={"source.py": material})
    assert verified["verified"] and verified["verdict"] == "proved"
    artifact.write_text("""print('changed')
""")
    tampered = verify_build_provenance(statement, subject_paths={"app.py": artifact})
    assert tampered["verdict"] == "refuted" and not tampered["verified"]
    with pytest.raises(ValueError): create_build_provenance({"app.py": artifact}, builder_id="x",
        command_argv="python app.py", build_type="test")
