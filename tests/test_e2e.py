"""End-to-end CLI tests (§9.1 exit codes and output schemas)."""

import io
import json
import os
import sys
import tempfile

import pyfusa
from pyfusa.cli.main import run


#fusa:test REQ-FUSA001
def test_version_text():
    out = io.StringIO()
    code = run(["version"], stdout=out)
    assert code == pyfusa.EXIT_OK
    line = out.getvalue().strip()
    assert line.startswith("py-FuSa")
    assert pyfusa.VERSION in line


#fusa:test REQ-FUSA001
def test_version_json():
    out = io.StringIO()
    code = run(["version", "--format", "json"], stdout=out)
    assert code == pyfusa.EXIT_OK
    doc = json.loads(out.getvalue())
    assert doc["tool"] == "py-FuSa"
    assert doc["version"] == pyfusa.VERSION
    assert doc["specVersion"] == pyfusa.SPEC_VERSION


#fusa:test REQ-FUSA001
def test_capabilities_json():
    out = io.StringIO()
    code = run(["capabilities", "--format", "json"], stdout=out)
    assert code == pyfusa.EXIT_OK
    doc = json.loads(out.getvalue())
    assert doc["kind"] == "capabilities"
    assert doc["language"] == "python"
    assert "commands" in doc
    assert "check" in doc["commands"]


#fusa:test REQ-FUSA001
def test_unknown_command():
    err = io.StringIO()
    code = run(["notacommand"], stderr=err)
    assert code == pyfusa.EXIT_USAGE


#fusa:test REQ-FUSA001
def test_no_args():
    out = io.StringIO()
    code = run([], stdout=out)
    assert code == pyfusa.EXIT_USAGE


#fusa:test REQ-FUSA001
def test_check_exit_1_on_errors():
    with tempfile.TemporaryDirectory() as tmpdir:
        # No .fusa.json → FUSA001 ERROR
        out = io.StringIO()
        err = io.StringIO()
        code = run(["check", "--dir", tmpdir, "--format", "json"], stdout=out, stderr=err)
        assert code == pyfusa.EXIT_GATE_FAIL
        doc = json.loads(out.getvalue())
        assert doc["schemaVersion"] == pyfusa.SPEC_VERSION
        assert doc["kind"] == "check-report"
        assert any(f["ruleId"] == "FUSA001" for f in doc["findings"])


#fusa:test REQ-FUSA001
def test_check_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        run(["check", "--dir", tmpdir, "--format", "json"], stdout=out)
        doc = json.loads(out.getvalue())
        assert "schemaVersion" in doc
        assert "kind" in doc
        assert "tool" in doc
        assert "toolVersion" in doc
        assert "language" in doc
        assert "generatedAt" in doc
        assert "findings" in doc
        assert "summary" in doc


#fusa:test REQ-FUSA001
def test_report_always_exits_0():
    with tempfile.TemporaryDirectory() as tmpdir:
        # Even with errors, report exits 0
        out = io.StringIO()
        code = run(["report", "--dir", tmpdir, "--format", "json"], stdout=out)
        assert code == pyfusa.EXIT_OK


#fusa:test REQ-FUSA001
def test_report_strict_is_usage_error():
    with tempfile.TemporaryDirectory() as tmpdir:
        err = io.StringIO()
        code = run(["report", "--dir", tmpdir, "--strict"], stderr=err)
        assert code == pyfusa.EXIT_USAGE


#fusa:test REQ-FUSA001
def test_check_output_to_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        out_file = os.path.join(tmpdir, "out.json")
        out = io.StringIO()
        run(["check", "--dir", tmpdir, "--format", "json", "--output", out_file], stdout=out)
        # stdout should be empty when --output is set
        assert out.getvalue() == ""
        assert os.path.exists(out_file)
        with open(out_file) as f:
            doc = json.load(f)
        assert "findings" in doc


#fusa:test REQ-FUSA001
def test_init_creates_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            ["init", "--dir", tmpdir, "--name", "myproj", "--standard", "iso26262"],
            stdout=out,
        )
        assert code == pyfusa.EXIT_OK
        assert os.path.exists(os.path.join(tmpdir, ".fusa.json"))
        assert os.path.exists(os.path.join(tmpdir, ".fusa-reqs.json"))


#fusa:test REQ-FUSA001
def test_init_fusa_json_content():
    with tempfile.TemporaryDirectory() as tmpdir:
        run(["init", "--dir", tmpdir, "--name", "myproj", "--standard", "iec61508", "--sil", "SIL-2"])
        with open(os.path.join(tmpdir, ".fusa.json")) as f:
            doc = json.load(f)
        assert doc["project"]["name"] == "myproj"
        assert doc["standard"] == "iec61508"
        assert doc["sil"] == "SIL-2"


#fusa:test REQ-FUSA001
def test_init_no_name_in_ci_fails():
    with tempfile.TemporaryDirectory() as tmpdir:
        err = io.StringIO()
        # stdin not a tty in test environment
        code = run(["init", "--dir", tmpdir, "--standard", "iso26262"], stderr=err)
        assert code == pyfusa.EXIT_USAGE


#fusa:test REQ-FUSA001
def test_qualify_exits_0_all_pass():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["qualify", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK


#fusa:test REQ-FUSA001
def test_qualify_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["qualify", "--dir", tmpdir, "--format", "json"], stdout=out)
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "qualification"
        assert "total" in doc
        assert "passed" in doc
        assert "failed" in doc
        assert "results" in doc
        assert "hash" in doc


#fusa:test REQ-FUSA001
def test_trace_json_schema():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["trace", "--dir", tmpdir, "--format", "json"], stdout=out)
        assert code == pyfusa.EXIT_OK
        doc = json.loads(out.getvalue())
        assert doc["kind"] == "trace-matrix"
        assert "requirements" in doc
        assert "tags" in doc
        assert "coverage" in doc


#fusa:test REQ-FUSA001
def test_release_json_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["release", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK
        assert os.path.exists(os.path.join(tmpdir, "sbom.json"))
        assert os.path.exists(os.path.join(tmpdir, "provenance.json"))
        assert os.path.exists(os.path.join(tmpdir, "artifact-manifest.json"))


#fusa:test REQ-FUSA001
def test_audit_pack_command():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(["audit-pack", "--dir", tmpdir], stdout=out)
        assert code == pyfusa.EXIT_OK
        assert os.path.exists(os.path.join(tmpdir, "audit-pack.zip"))


#fusa:test REQ-FUSA001
def test_no_color_flag_strips_ansi():
    out = io.StringIO()
    err = io.StringIO()
    code = run(["--no-color", "version"], stdout=out, stderr=err)
    assert code == pyfusa.EXIT_OK
    assert "\x1b[" not in out.getvalue()


#fusa:test REQ-FUSA001
def test_check_sarif_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        run(["check", "--dir", tmpdir, "--format", "sarif"], stdout=out)
        doc = json.loads(out.getvalue())
        assert doc["version"] == "2.1.0"
        assert "runs" in doc
        assert doc["runs"][0]["tool"]["driver"]["name"] == "py-FuSa"
