"""Tests for trace command (§5)."""

import json
import os
import tempfile

import pyfusa
from pyfusa.config import default
import pyfusa.trace as trace


def _write_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


#fusa:test REQ-FUSA001
def test_trace_empty_project():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        assert matrix.coverage.total_requirements == 0


#fusa:test REQ-FUSA001
def test_trace_scans_req_annotations():
    with tempfile.TemporaryDirectory() as tmpdir:
        reqs = {"requirements": [{"id": "REQ-001", "title": "Test req"}]}
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump(reqs, f)
        src = "#fusa:req REQ-001\ndef foo():\n    pass\n"
        _write_file(os.path.join(tmpdir, "src", "foo.py"), src)
        cfg = default()
        cfg.source_dirs = ["."]
        matrix = trace.build(tmpdir, cfg)
        assert matrix.coverage.total_requirements == 1
        assert matrix.coverage.traced_requirements == 1


#fusa:test REQ-FUSA001
def test_trace_scans_test_annotations():
    with tempfile.TemporaryDirectory() as tmpdir:
        reqs = {"requirements": [{"id": "REQ-001", "title": "Test req"}]}
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump(reqs, f)
        src = "#fusa:test REQ-001\ndef test_foo():\n    pass\n"
        _write_file(os.path.join(tmpdir, "test_foo.py"), src)
        cfg = default()
        cfg.source_dirs = ["."]
        matrix = trace.build(tmpdir, cfg)
        assert matrix.coverage.tested_requirements == 1


#fusa:test REQ-FUSA001
def test_trace_sec_test_counts_toward_tested():
    with tempfile.TemporaryDirectory() as tmpdir:
        reqs = {"requirements": [{"id": "REQ-SEC001", "title": "Security req"}]}
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump(reqs, f)
        src = "#fusa:sec-test REQ-SEC001\ndef test_sec():\n    pass\n"
        _write_file(os.path.join(tmpdir, "test_sec.py"), src)
        cfg = default()
        cfg.source_dirs = ["."]
        matrix = trace.build(tmpdir, cfg)
        assert matrix.coverage.sec_tested_requirements == 1
        assert matrix.coverage.tested_requirements == 1


#fusa:test REQ-FUSA001
def test_trace_json_output_has_envelope():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="myproj", standard="iso26262")
        matrix = trace.build(tmpdir, cfg)
        doc = trace.to_dict(matrix, tmpdir, cfg)
        assert doc["schemaVersion"] == pyfusa.SPEC_VERSION
        assert doc["kind"] == "trace-matrix"
        assert doc["language"] == "python"
        assert "coverage" in doc


#fusa:test REQ-FUSA001
def test_trace_gaps_only_filters():
    with tempfile.TemporaryDirectory() as tmpdir:
        reqs = {"requirements": [
            {"id": "REQ-001", "title": "Tested"},
            {"id": "REQ-002", "title": "Not tested"},
        ]}
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump(reqs, f)
        src = "#fusa:test REQ-001\ndef test_foo():\n    pass\n"
        _write_file(os.path.join(tmpdir, "test_foo.py"), src)
        cfg = default()
        cfg.source_dirs = ["."]
        matrix = trace.build(tmpdir, cfg)
        doc = trace.to_dict(matrix, tmpdir, cfg, gaps_only=True)
        req_ids = [r["id"] for r in doc["requirements"]]
        assert "REQ-002" in req_ids
        assert "REQ-001" not in req_ids
        # But coverage still has full totals (§5)
        assert doc["coverage"]["totalRequirements"] == 2
