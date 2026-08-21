"""Tests for release command (§7)."""

import io
import json
import os
import tempfile

import pyfusa
import pyfusa.release as release
import pyfusa.vuln as vuln
from pyfusa.cli.main import run
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


# fusa:test REQ-FUSA001
def test_release_full_emits_fmea_boundary_vuln_and_audit_pack(monkeypatch):
    """§7: --full MUST emit the output of every implemented component
    (fmea.json, fmea.csv, boundary.dot, boundary.mermaid, vuln.json) and
    finally audit-pack.zip. A prior revision only ever wrote the base three
    (sbom/provenance/artifact-manifest) plus audit-pack.zip, skipping the
    five in between despite implementing all of them."""
    # vuln.scan() hits the live OSV API by default — stub it so this test
    # stays hermetic and fast.
    monkeypatch.setattr(
        vuln, "scan", lambda root, cfg, timeout=30: {"kind": "vuln-report", "findings": []}
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        open(os.path.join(tmpdir, ".fusa.json"), "w").write(
            '{"project":{"name":"t"}}'
        )
        open(os.path.join(tmpdir, "mod.py"), "w").write("def f(x):\n    return x\n")

        code = run(["release", "--dir", tmpdir, "--full"], stdout=io.StringIO())
        assert code == pyfusa.EXIT_OK
        for fname in (
            "sbom.json",
            "provenance.json",
            "artifact-manifest.json",
            "fmea.json",
            "fmea.csv",
            "boundary.dot",
            "boundary.mermaid",
            "vuln.json",
            "audit-pack.zip",
        ):
            assert os.path.exists(os.path.join(tmpdir, fname)), f"missing {fname}"


# fusa:test REQ-FUSA001
def test_release_full_skips_gracefully_on_component_failure(monkeypatch):
    """A runtime failure generating one --full component (e.g. fmea) must
    not abort the rest of --full — the other components and audit-pack.zip
    still get attempted, with a warning on stderr for the failed one."""
    import pyfusa.fmea as fmea

    def _boom(*a, **kw):
        raise RuntimeError("boom")

    monkeypatch.setattr(fmea, "scan", _boom)
    monkeypatch.setattr(
        vuln, "scan", lambda root, cfg, timeout=30: {"kind": "vuln-report", "findings": []}
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        open(os.path.join(tmpdir, ".fusa.json"), "w").write(
            '{"project":{"name":"t"}}'
        )
        open(os.path.join(tmpdir, "mod.py"), "w").write("def f(x):\n    return x\n")

        err = io.StringIO()
        code = run(
            ["release", "--dir", tmpdir, "--full"], stdout=io.StringIO(), stderr=err
        )
        assert code == pyfusa.EXIT_OK
        assert "fmea.json" in err.getvalue()
        assert not os.path.exists(os.path.join(tmpdir, "fmea.json"))
        # the rest still ran, including audit-pack.zip last
        assert os.path.exists(os.path.join(tmpdir, "boundary.dot"))
        assert os.path.exists(os.path.join(tmpdir, "audit-pack.zip"))
