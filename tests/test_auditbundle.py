import hashlib
import json
import zipfile

from pegrex.auditbundle import create_audit_bundle, verify_audit_bundle


def test_audit_bundle_is_reproducible_and_verifies_offline(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("print('ok')\n")
    first = create_audit_bundle(root, tmp_path / "one.zip", configuration={"rules": "v1"},
                                reports={"findings": []}, coverage={"status": "complete"},
                                include_sources=True, osv_snapshot={"version": "offline-test"})
    second = create_audit_bundle(root, tmp_path / "two.zip", configuration={"rules": "v1"},
                                 reports={"findings": []}, coverage={"status": "complete"},
                                 include_sources=True, osv_snapshot={"version": "offline-test"})
    assert first["sha256"] == second["sha256"]
    verified = verify_audit_bundle(tmp_path / "one.zip", root=root)
    assert verified["ok"] and verified["stable"]
    with zipfile.ZipFile(tmp_path / "one.zip") as archive:
        manifest = json.loads(archive.read("manifest.json"))
        assert manifest["provenance"]["network"] == "offline"
        assert manifest["sources"][0]["sha256"] == hashlib.sha256(b"print('ok')\n").hexdigest()


def test_source_drift_is_visible_not_bundle_tampering(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    source = root / "app.py"
    source.write_text("x = 1\n")
    create_audit_bundle(root, tmp_path / "audit.zip")
    source.write_text("x = 2\n")
    result = verify_audit_bundle(tmp_path / "audit.zip", root=root)
    assert result["ok"]
    assert not result["stable"]
    assert result["drift"][0]["path"] == "app.py"


def test_missing_coverage_is_explicit_unknown(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n")
    create_audit_bundle(root, tmp_path / "audit.zip")
    with zipfile.ZipFile(tmp_path / "audit.zip") as archive:
        coverage = json.loads(archive.read("evidence/coverage.json"))
    assert coverage["status"] == "unknown"
