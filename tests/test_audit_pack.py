"""Tests for audit-pack command (§8)."""

import json
import os
import tempfile
import zipfile

import pyfusa.auditpack as auditpack
from pyfusa.config import default


#fusa:test REQ-FUSA001
def test_auditpack_creates_zip():
    with tempfile.TemporaryDirectory() as tmpdir:
        pack_path = auditpack.create(tmpdir)
        assert os.path.exists(pack_path)
        assert pack_path.endswith(".zip")


#fusa:test REQ-FUSA001
def test_auditpack_is_valid_zip():
    with tempfile.TemporaryDirectory() as tmpdir:
        pack_path = auditpack.create(tmpdir)
        assert zipfile.is_zipfile(pack_path)


#fusa:test REQ-FUSA001
def test_auditpack_contains_manifest():
    with tempfile.TemporaryDirectory() as tmpdir:
        pack_path = auditpack.create(tmpdir)
        with zipfile.ZipFile(pack_path) as zf:
            names = zf.namelist()
        assert "manifest.json" in names


#fusa:test REQ-FUSA001
def test_auditpack_manifest_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        pack_path = auditpack.create(tmpdir)
        with zipfile.ZipFile(pack_path) as zf:
            manifest_bytes = zf.read("manifest.json")
        manifest = json.loads(manifest_bytes)
        import pyfusa
        assert manifest["schemaVersion"] == pyfusa.SPEC_VERSION
        assert manifest["kind"] == "audit-manifest"
        assert "files" in manifest


#fusa:test REQ-FUSA001
def test_auditpack_flat_structure():
    """§8: entries must be flat at the ZIP root (no subdirectory)."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa.json"), "w") as f:
            json.dump({"configVersion": "1.0", "project": {"name": "test"}, "standard": "iso26262"}, f)
        pack_path = auditpack.create(tmpdir)
        with zipfile.ZipFile(pack_path) as zf:
            for name in zf.namelist():
                assert "/" not in name, f"entry {name!r} is not flat"


#fusa:test REQ-FUSA001
def test_auditpack_does_not_contain_itself():
    """§8: audit-pack.zip must not include itself."""
    with tempfile.TemporaryDirectory() as tmpdir:
        pack_path = auditpack.create(tmpdir)
        with zipfile.ZipFile(pack_path) as zf:
            assert "audit-pack.zip" not in zf.namelist()


#fusa:test REQ-FUSA001
def test_auditpack_packs_fusa_json():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa.json"), "w") as f:
            json.dump({"configVersion": "1.0", "project": {"name": "test"}, "standard": "iso26262"}, f)
        pack_path = auditpack.create(tmpdir)
        with zipfile.ZipFile(pack_path) as zf:
            assert ".fusa.json" in zf.namelist()


#fusa:test REQ-FUSA001
def test_auditpack_sha256_in_manifest():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa.json"), "w") as f:
            f.write('{"configVersion":"1.0","project":{"name":"x"},"standard":"iso26262"}')
        pack_path = auditpack.create(tmpdir)
        with zipfile.ZipFile(pack_path) as zf:
            manifest = json.loads(zf.read("manifest.json"))
        for entry in manifest["files"]:
            assert "sha256" in entry
            assert len(entry["sha256"]) == 64
