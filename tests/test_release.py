"""Tests for release command (§7)."""

import json
import os
import tempfile

import pyfusa
import pyfusa.release as release
from pyfusa.config import default


# fusa:test REQ-FUSA001
def test_release_writes_sbom():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="myproj")
        written = release.run_release(tmpdir, cfg, tmpdir)
        sbom_path = os.path.join(tmpdir, "sbom.json")
        assert os.path.exists(sbom_path)


# fusa:test REQ-FUSA001
def test_sbom_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="myproj")
        release.run_release(tmpdir, cfg, tmpdir)
        with open(os.path.join(tmpdir, "sbom.json")) as f:
            doc = json.load(f)
        assert doc["schemaVersion"] == pyfusa.SPEC_VERSION
        assert doc["kind"] == "sbom"
        assert doc["language"] == "python"
        assert "module" in doc
        assert "components" in doc


# fusa:test REQ-FUSA001
def test_provenance_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="myproj")
        release.run_release(tmpdir, cfg, tmpdir)
        with open(os.path.join(tmpdir, "provenance.json")) as f:
            doc = json.load(f)
        assert doc["kind"] == "provenance"
        assert "vcsRevision" in doc
        assert "vcsModified" in doc


# fusa:test REQ-FUSA001
def test_artifact_manifest_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="myproj")
        release.run_release(tmpdir, cfg, tmpdir)
        with open(os.path.join(tmpdir, "artifact-manifest.json")) as f:
            doc = json.load(f)
        assert doc["kind"] == "artifact-manifest"
        assert "artifacts" in doc
        for a in doc["artifacts"]:
            assert "path" in a
            assert "sha256" in a


# fusa:test REQ-FUSA001
def test_release_creates_output_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="myproj")
        output_dir = os.path.join(tmpdir, "release-out")
        assert not os.path.exists(output_dir)
        release.run_release(tmpdir, cfg, output_dir)
        assert os.path.exists(output_dir)
