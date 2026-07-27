"""Tests for trace command (§5)."""

import io
import json
import os
import tempfile

import pyfusa
from pyfusa.cli.main import run
from pyfusa.config import default
import pyfusa.trace as trace


def _write_file(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


# fusa:test REQ-FUSA001
def test_trace_empty_project():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        assert matrix.coverage.total_requirements == 0


# fusa:test REQ-FUSA001
def test_trace_scans_req_annotations():
    with tempfile.TemporaryDirectory() as tmpdir:
        reqs = {"requirements": [{"id": "REQ-001", "title": "Test req"}]}
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump(reqs, f)
        # NOTE: built via adjacent-literal concatenation ("#" + "fusa:req ...")
        # rather than one contiguous literal so this fixture's own source
        # line in this file is not itself mistaken for a real annotation
        # when the real project's test tree is scanned (§1.4.1 scan-path
        # completeness always includes tests/).
        src = "#" + "fusa:req REQ-001\ndef foo():\n    pass\n"
        _write_file(os.path.join(tmpdir, "src", "foo.py"), src)
        cfg = default()
        cfg.source_dirs = ["."]
        matrix = trace.build(tmpdir, cfg)
        assert matrix.coverage.total_requirements == 1
        assert matrix.coverage.traced_requirements == 1


# fusa:test REQ-FUSA001
def test_trace_scans_test_annotations():
    with tempfile.TemporaryDirectory() as tmpdir:
        reqs = {"requirements": [{"id": "REQ-001", "title": "Test req"}]}
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump(reqs, f)
        # See NOTE above re: adjacent-literal concatenation.
        src = "#" + "fusa:test REQ-001\ndef test_foo():\n    pass\n"
        _write_file(os.path.join(tmpdir, "test_foo.py"), src)
        cfg = default()
        cfg.source_dirs = ["."]
        matrix = trace.build(tmpdir, cfg)
        assert matrix.coverage.tested_requirements == 1


# fusa:test REQ-FUSA001
def test_trace_sec_test_counts_toward_tested():
    with tempfile.TemporaryDirectory() as tmpdir:
        reqs = {"requirements": [{"id": "REQ-SEC001", "title": "Security req"}]}
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump(reqs, f)
        # See NOTE above re: adjacent-literal concatenation.
        src = "#" + "fusa:sec-test REQ-SEC001\ndef test_sec():\n    pass\n"
        _write_file(os.path.join(tmpdir, "test_sec.py"), src)
        cfg = default()
        cfg.source_dirs = ["."]
        matrix = trace.build(tmpdir, cfg)
        assert matrix.coverage.sec_tested_requirements == 1
        assert matrix.coverage.tested_requirements == 1


# fusa:test REQ-FUSA001
def test_trace_json_output_has_envelope():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="myproj", standard="iso26262")
        matrix = trace.build(tmpdir, cfg)
        doc = trace.to_dict(matrix, tmpdir, cfg)
        assert doc["schemaVersion"] == pyfusa.SPEC_VERSION
        assert doc["kind"] == "trace-matrix"
        assert doc["language"] == "python"
        assert "coverage" in doc


# fusa:test REQ-FUSA001
def test_trace_gaps_only_filters():
    with tempfile.TemporaryDirectory() as tmpdir:
        reqs = {
            "requirements": [
                {"id": "REQ-001", "title": "Tested"},
                {"id": "REQ-002", "title": "Not tested"},
            ]
        }
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump(reqs, f)
        # See NOTE above (test_trace_scans_req_annotations) re: adjacent-
        # literal concatenation.
        src = "#" + "fusa:test REQ-001\ndef test_foo():\n    pass\n"
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


# ---------------------------------------------------------------------------
# §1.4.1 scan-path completeness — tests/ is always scanned regardless of
# sourceDirs (bug: previously sourceDirs=["pyfusa"]-style configs meant the
# test tree was never scanned, so testedRequirements was silently wrong).
# ---------------------------------------------------------------------------


# fusa:test REQ-TRACE001
def test_scan_always_includes_tests_dir_even_when_excluded_from_source_dirs():
    with tempfile.TemporaryDirectory() as tmpdir:
        reqs = {"requirements": [{"id": "REQ-100", "title": "Some req"}]}
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump(reqs, f)
        _write_file(
            os.path.join(tmpdir, "tests", "test_thing.py"),
            "#" + "fusa:test REQ-100\ndef test_thing():\n    pass\n",
        )
        cfg = default()
        cfg.source_dirs = ["src"]  # deliberately does NOT mention tests/
        matrix = trace.build(tmpdir, cfg)
        assert matrix.coverage.tested_requirements == 1


# fusa:test REQ-TRACE001
def test_scan_test_dir_not_double_scanned_when_already_covered():
    with tempfile.TemporaryDirectory() as tmpdir:
        reqs = {"requirements": [{"id": "REQ-100", "title": "Some req"}]}
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump(reqs, f)
        _write_file(
            os.path.join(tmpdir, "tests", "test_thing.py"),
            "#" + "fusa:test REQ-100\ndef test_thing():\n    pass\n",
        )
        cfg = default()
        cfg.source_dirs = ["."]  # already covers tests/ as a subdirectory
        matrix = trace.build(tmpdir, cfg)
        matching = [t for t in matrix.tags if t.requirement_id == "REQ-100"]
        assert len(matching) == 1


# fusa:test REQ-TRACE001
def test_scan_test_alias_dir_also_included():
    """The singular "test" directory name is also always scanned."""
    with tempfile.TemporaryDirectory() as tmpdir:
        reqs = {"requirements": [{"id": "REQ-100", "title": "Some req"}]}
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump(reqs, f)
        _write_file(
            os.path.join(tmpdir, "test", "test_thing.py"),
            "#" + "fusa:test REQ-100\ndef test_thing():\n    pass\n",
        )
        cfg = default()
        cfg.source_dirs = ["src"]
        matrix = trace.build(tmpdir, cfg)
        assert matrix.coverage.tested_requirements == 1


# ---------------------------------------------------------------------------
# §1.4.1.3 dangling test/sec-test tag reference detection (REQ004, WARNING)
# ---------------------------------------------------------------------------


# fusa:test REQ-TRACE001
def test_dangling_test_tag_produces_warning_finding():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump({"requirements": []}, f)
        _write_file(
            os.path.join(tmpdir, "tests", "test_thing.py"),
            "#" + "fusa:test REQ-DOES-NOT-EXIST\ndef test_thing():\n    pass\n",
        )
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        dangling = [f for f in matrix.findings if f.rule_id == "REQ004"]
        assert len(dangling) == 1
        assert dangling[0].severity == pyfusa.SEVERITY_WARNING
        assert dangling[0].category == pyfusa.CATEGORY_REQUIREMENT
        assert "REQ-DOES-NOT-EXIST" in dangling[0].message


# fusa:test REQ-TRACE001
def test_dangling_sec_test_tag_also_flagged():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump({"requirements": []}, f)
        _write_file(
            os.path.join(tmpdir, "tests", "test_thing.py"),
            "#" + "fusa:sec-test REQ-GHOST\ndef test_thing():\n    pass\n",
        )
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        dangling = [f for f in matrix.findings if f.rule_id == "REQ004"]
        assert any("REQ-GHOST" in f.message for f in dangling)


# fusa:test REQ-TRACE001
def test_dangling_impl_tag_not_flagged():
    """Only test/sec-test kind tags are checked for dangling references (§1.4.1.3);
    impl tags are out of scope for this specific check."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump({"requirements": []}, f)
        _write_file(
            os.path.join(tmpdir, "src", "mod.py"),
            "#" + "fusa:req REQ-GHOST-IMPL\ndef foo():\n    pass\n",
        )
        cfg = default()
        cfg.source_dirs = ["src"]
        matrix = trace.build(tmpdir, cfg)
        dangling = [f for f in matrix.findings if f.rule_id == "REQ004"]
        assert dangling == []


# fusa:test REQ-TRACE001
def test_registered_test_tag_not_flagged_dangling():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump({"requirements": [{"id": "REQ-100", "title": "x"}]}, f)
        _write_file(
            os.path.join(tmpdir, "tests", "test_thing.py"),
            "#" + "fusa:test REQ-100\ndef test_thing():\n    pass\n",
        )
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        dangling = [f for f in matrix.findings if f.rule_id == "REQ004"]
        assert dangling == []


# fusa:test REQ-TRACE001
def test_dangling_findings_appear_in_json_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump({"requirements": []}, f)
        _write_file(
            os.path.join(tmpdir, "tests", "test_thing.py"),
            "#" + "fusa:test REQ-GHOST\ndef test_thing():\n    pass\n",
        )
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        doc = trace.to_dict(matrix, tmpdir, cfg)
        assert "findings" in doc
        assert any(f["ruleId"] == "REQ004" for f in doc["findings"])


# fusa:test REQ-TRACE001
def test_dangling_findings_appear_in_text_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            json.dump({"requirements": []}, f)
        _write_file(
            os.path.join(tmpdir, "tests", "test_thing.py"),
            "#" + "fusa:test REQ-GHOST\ndef test_thing():\n    pass\n",
        )
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        text = trace.render_text(matrix)
        assert "REQ004" in text
        assert "REQ-GHOST" in text


# fusa:test REQ-TRACE001
def test_no_findings_key_when_no_findings():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        doc = trace.to_dict(matrix, tmpdir, cfg)
        assert "findings" not in doc


# ---------------------------------------------------------------------------
# §1.4.1.2 / §5 --func-coverage
# ---------------------------------------------------------------------------


# fusa:test REQ-TRACE001
def test_compute_func_coverage_class_level_tag_covers_methods():
    with tempfile.TemporaryDirectory() as tmpdir:
        # See NOTE (test_trace_scans_req_annotations) re: adjacent-literal
        # concatenation avoiding a self-match when tests/ is scanned.
        _write_file(
            os.path.join(tmpdir, "pkg", "mod.py"),
            "#" + " fusa:req REQ-X\n"
            "class Widget:\n"
            "    def public_method(self):\n"
            "        pass\n"
            "\n"
            "    def _private(self):\n"
            "        pass\n"
            "\n"
            "    def __init__(self):\n"
            "        pass\n",
        )
        cfg = default()
        cfg.source_dirs = ["pkg"]
        tagged, total = trace.compute_func_coverage(tmpdir, cfg)
        # Only the public, non-dunder method counts.
        assert total == 1
        assert tagged == 1


# fusa:test REQ-TRACE001
def test_compute_func_coverage_untagged_function_not_counted_as_tagged():
    with tempfile.TemporaryDirectory() as tmpdir:
        # See NOTE (test_trace_scans_req_annotations) re: adjacent-literal
        # concatenation avoiding a self-match when tests/ is scanned.
        _write_file(
            os.path.join(tmpdir, "pkg", "mod.py"),
            "def untagged():\n"
            "    pass\n"
            "\n"
            "\n"
            "#" + " fusa:req REQ-Y\n"
            "def tagged():\n"
            "    pass\n",
        )
        cfg = default()
        cfg.source_dirs = ["pkg"]
        tagged, total = trace.compute_func_coverage(tmpdir, cfg)
        assert total == 2
        assert tagged == 1


# fusa:test REQ-TRACE001
def test_compute_func_coverage_private_module_function_excluded():
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_file(
            os.path.join(tmpdir, "pkg", "mod.py"),
            "def _helper():\n    pass\n",
        )
        cfg = default()
        cfg.source_dirs = ["pkg"]
        tagged, total = trace.compute_func_coverage(tmpdir, cfg)
        assert total == 0
        assert tagged == 0


# fusa:test REQ-TRACE001
def test_compute_func_coverage_excludes_tests_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_file(
            os.path.join(tmpdir, "tests", "test_mod.py"),
            "def test_something():\n    pass\n",
        )
        cfg = default()
        cfg.source_dirs = ["tests"]
        tagged, total = trace.compute_func_coverage(tmpdir, cfg)
        assert total == 0
        assert tagged == 0


# fusa:test REQ-TRACE001
def test_compute_func_coverage_zero_when_no_python_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        cfg.source_dirs = ["nonexistent"]
        tagged, total = trace.compute_func_coverage(tmpdir, cfg)
        assert (tagged, total) == (0, 0)


# ---------------------------------------------------------------------------
# --func-coverage CLI gate (mirrors --req-coverage)
# ---------------------------------------------------------------------------


def _init_project(tmpdir: str, module_src: str) -> None:
    fusa_cfg = {
        "configVersion": "1.0",
        "project": {"name": "p"},
        "standard": "iso26262",
        "sourceDirs": ["pkg"],
    }
    with open(os.path.join(tmpdir, ".fusa.json"), "w") as f:
        json.dump(fusa_cfg, f)
    _write_file(os.path.join(tmpdir, "pkg", "mod.py"), module_src)


# fusa:test REQ-TRACE001
def test_func_coverage_zero_disables_gate():
    with tempfile.TemporaryDirectory() as tmpdir:
        _init_project(tmpdir, "def untagged():\n    pass\n")
        out = io.StringIO()
        err = io.StringIO()
        code = run(
            ["trace", "--dir", tmpdir, "--func-coverage", "0"], stdout=out, stderr=err
        )
        assert code == pyfusa.EXIT_OK


# fusa:test REQ-TRACE001
def test_func_coverage_below_threshold_exits_1():
    with tempfile.TemporaryDirectory() as tmpdir:
        _init_project(tmpdir, "def untagged():\n    pass\n")
        out = io.StringIO()
        err = io.StringIO()
        code = run(
            ["trace", "--dir", tmpdir, "--func-coverage", "100"],
            stdout=out,
            stderr=err,
        )
        assert code == pyfusa.EXIT_GATE_FAIL
        assert "func coverage" in err.getvalue()


# fusa:test REQ-TRACE001
def test_func_coverage_at_threshold_exits_0():
    with tempfile.TemporaryDirectory() as tmpdir:
        # See NOTE (test_trace_scans_req_annotations) re: adjacent-literal
        # concatenation avoiding a self-match when tests/ is scanned.
        _init_project(tmpdir, "#" + " fusa:req REQ-Z\ndef tagged():\n    pass\n")
        out = io.StringIO()
        err = io.StringIO()
        code = run(
            ["trace", "--dir", tmpdir, "--func-coverage", "100"],
            stdout=out,
            stderr=err,
        )
        assert code == pyfusa.EXIT_OK
