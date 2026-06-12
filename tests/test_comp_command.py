"""Tests for pyfusa/comp.py — standalone cyclomatic complexity report."""

from __future__ import annotations

import io
import json
import os
import tempfile

from pyfusa.config import default
from pyfusa.cli.main import run


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_SIMPLE_PY = """\
def simple(x):
    return x + 1


def branchy(x, y, z):
    if x:
        if y:
            return 1
        elif z:
            return 2
        else:
            return 3
    elif y and z:
        return 4
    else:
        return 5
"""

_COMPLEX_PY = """\
def very_complex(a, b, c, d, e):
    if a:
        if b:
            if c:
                if d:
                    if e:
                        return 1
                    else:
                        return 2
                elif d:
                    return 3
                else:
                    return 4
            elif c:
                return 5
            else:
                return 6
        elif b and c:
            return 7
        else:
            return 8
    elif a and b:
        return 9
    else:
        return 10
"""


def _make_project(tmpdir: str, content: str, filename: str = "mymod.py") -> str:
    open(os.path.join(tmpdir, ".fusa.json"),
         "w").write('{"project":{"name":"tp"},"standard":"iso26262","asil":"ASIL-B"}')
    open(os.path.join(tmpdir, filename), "w").write(content)
    return tmpdir


# ---------------------------------------------------------------------------
# pyfusa.comp module
# ---------------------------------------------------------------------------

def test_analyze_simple():
    import pyfusa.comp as comp
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, _SIMPLE_PY)
        cfg = default(project_name="tp")
        results, threshold = comp.analyze(tmpdir, cfg)
        names = [r.function for r in results]
        assert "simple" in names
        assert "branchy" in names


def test_analyze_skips_test_files():
    import pyfusa.comp as comp
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, _SIMPLE_PY, filename="test_something.py")
        cfg = default(project_name="tp")
        results, _ = comp.analyze(tmpdir, cfg)
        assert len(results) == 0


def test_analyze_skips_private_functions():
    import pyfusa.comp as comp
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, "def _private(x):\n    return x\n")
        cfg = default(project_name="tp")
        results, _ = comp.analyze(tmpdir, cfg)
        assert not any(r.function == "_private" for r in results)


def test_analyze_threshold_asil_b():
    import pyfusa.comp as comp
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, _COMPLEX_PY)
        cfg = default(project_name="tp"); cfg.asil = "ASIL-B"
        results, threshold = comp.analyze(tmpdir, cfg)
        assert threshold == 15
        # very_complex has V(G)~12, which is under the ASIL-B threshold of 15
        assert any(r.function == "very_complex" for r in results)


def test_analyze_threshold_asil_d():
    import pyfusa.comp as comp
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, _COMPLEX_PY)
        cfg = default(project_name="tp"); cfg.asil = "ASIL-D"
        results, threshold = comp.analyze(tmpdir, cfg)
        assert threshold == 4
        fails = [r for r in results if r.status == "FAIL"]
        assert len(fails) >= 1


def test_analyze_empty_dir():
    import pyfusa.comp as comp
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="tp")
        results, threshold = comp.analyze(tmpdir, cfg)
        assert results == []
        assert threshold == 10


def test_analyze_nonexistent_source_dir():
    import pyfusa.comp as comp
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="tp")
        cfg.source_dirs = ["nonexistent"]
        results, _ = comp.analyze(tmpdir, cfg)
        assert results == []


def test_run_returns_correct_schema():
    import pyfusa.comp as comp
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, _SIMPLE_PY)
        cfg = default(project_name="tp")
        doc = comp.run(tmpdir, cfg)
        assert doc["kind"] == "comp-report"
        assert doc["standard"] == "DO-178C §6.3.4"
        assert "schemaVersion" in doc
        assert "tool" in doc
        assert "toolVersion" in doc
        assert "generatedAt" in doc
        assert "projectRoot" in doc
        assert "threshold" in doc
        assert "summary" in doc
        assert "functions" in doc


def test_run_summary_counts():
    import pyfusa.comp as comp
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, _SIMPLE_PY)
        cfg = default(project_name="tp")
        doc = comp.run(tmpdir, cfg)
        s = doc["summary"]
        assert s["total"] == s["pass"] + s["fail"]
        assert s["total"] == len(doc["functions"])


def test_run_function_fields():
    import pyfusa.comp as comp
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, _SIMPLE_PY)
        cfg = default(project_name="tp")
        doc = comp.run(tmpdir, cfg)
        for fn in doc["functions"]:
            assert "file" in fn
            assert "function" in fn
            assert "complexity" in fn
            assert "line" in fn
            assert fn["status"] in ("PASS", "FAIL")


def test_run_fail_status_for_complex():
    import pyfusa.comp as comp
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, _COMPLEX_PY)
        cfg = default(project_name="tp"); cfg.asil = "ASIL-D"  # threshold=4
        doc = comp.run(tmpdir, cfg)
        fails = [f for f in doc["functions"] if f["status"] == "FAIL"]
        assert len(fails) >= 1
        assert any(f["function"] == "very_complex" for f in fails)


def test_render_text_no_fails():
    import pyfusa.comp as comp
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, _SIMPLE_PY)
        cfg = default(project_name="myproj")
        doc = comp.run(tmpdir, cfg)
        text = comp.render_text(doc)
        assert "myproj" in text
        assert "total=" in text
        assert "All functions within threshold." in text


def test_render_text_with_fails():
    import pyfusa.comp as comp
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, _COMPLEX_PY)
        cfg = default(project_name="myproj"); cfg.asil = "ASIL-D"
        doc = comp.run(tmpdir, cfg)
        text = comp.render_text(doc)
        assert "FAIL" in text
        assert "very_complex" in text
        assert "✗" in text


def test_render_text_header():
    import pyfusa.comp as comp
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default(project_name="myproj")
        doc = comp.run(tmpdir, cfg)
        text = comp.render_text(doc)
        assert "Cyclomatic complexity report" in text
        assert "threshold=" in text


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def test_comp_cli_writes_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, _SIMPLE_PY)
        out = io.StringIO()
        err = io.StringIO()
        code = run(["comp", "--dir", tmpdir], stdout=out, stderr=err)
        assert code in (0, 1, 3)
        assert os.path.exists(os.path.join(tmpdir, "comp-report.json"))
        assert "Complexity:" in out.getvalue()
        assert "wrote comp-report.json" in out.getvalue()


def test_comp_cli_json_format():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, _SIMPLE_PY)
        out = io.StringIO()
        err = io.StringIO()
        code = run(["comp", "--dir", tmpdir, "--format", "json"], stdout=out, stderr=err)
        assert code in (0, 1, 3)
        report_path = os.path.join(tmpdir, "comp-report.json")
        with open(report_path) as f:
            doc = json.load(f)
        assert doc["kind"] == "comp-report"


def test_comp_cli_custom_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, _SIMPLE_PY)
        out_path = os.path.join(tmpdir, "custom.json")
        out = io.StringIO()
        err = io.StringIO()
        code = run(["comp", "--dir", tmpdir, "--format", "json", "--output", out_path],
                   stdout=out, stderr=err)
        assert code in (0, 1, 3)
        assert os.path.exists(out_path)
        with open(out_path) as f:
            doc = json.load(f)
        assert doc["kind"] == "comp-report"


def test_comp_cli_exit_gate_fail_on_violations():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, _COMPLEX_PY)
        open(os.path.join(tmpdir, ".fusa.json"), "w").write(
            '{"project":{"name":"tp"},"standard":"iso26262","asil":"ASIL-D"}'
        )
        out = io.StringIO()
        err = io.StringIO()
        code = run(["comp", "--dir", tmpdir], stdout=out, stderr=err)
        assert code == 1  # EXIT_GATE_FAIL


def test_comp_cli_exit_ok_no_violations():
    with tempfile.TemporaryDirectory() as tmpdir:
        _make_project(tmpdir, _SIMPLE_PY)
        out = io.StringIO()
        err = io.StringIO()
        code = run(["comp", "--dir", tmpdir], stdout=out, stderr=err)
        assert code == 0  # EXIT_OK — simple functions all pass ASIL-B threshold
