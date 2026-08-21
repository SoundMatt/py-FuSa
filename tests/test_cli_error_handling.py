"""Regression tests for CLI-layer error-handling gaps found during a
follow-up authenticity/quality audit of py-FuSa's own code: commands that
raised unhandled exceptions on ordinary bad input instead of a clean
EXIT_RUNTIME/EXIT_USAGE, an unvalidated enum flag that silently persisted a
bogus value into a compliance artifact, and a command that could succeed
completely silently."""

from __future__ import annotations

import io
import json
import os
import tempfile

import pyfusa
from pyfusa.cli.main import run

# ---------------------------------------------------------------------------
# req import/export -- unhandled FileNotFoundError
# ---------------------------------------------------------------------------


def test_req_import_missing_file_is_clean_runtime_error():
    err = io.StringIO()
    code = run(
        ["req", "import", "--file", "/nonexistent/path/does-not-exist.csv"],
        stdout=io.StringIO(),
        stderr=err,
    )
    assert code == pyfusa.EXIT_RUNTIME
    assert "No such file" in err.getvalue() or "not" in err.getvalue().lower()


def test_req_export_unwritable_path_is_clean_runtime_error():
    err = io.StringIO()
    with tempfile.TemporaryDirectory() as tmpdir:
        bad_path = os.path.join(tmpdir, "nonexistent-subdir", "out.csv")
        code = run(
            ["req", "export", "--dir", tmpdir, "--file", bad_path],
            stdout=io.StringIO(),
            stderr=err,
        )
    assert code == pyfusa.EXIT_RUNTIME


# ---------------------------------------------------------------------------
# badge -- unhandled JSONDecodeError on a malformed check-report.json
# ---------------------------------------------------------------------------


def test_badge_malformed_report_is_clean_runtime_error():
    err = io.StringIO()
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "check-report.json"), "w") as f:
            f.write("not valid json")
        code = run(["badge", "--dir", tmpdir], stdout=io.StringIO(), stderr=err)
    assert code == pyfusa.EXIT_RUNTIME
    assert err.getvalue()


# ---------------------------------------------------------------------------
# impact -- malformed sibling files degrade gracefully (matching
# config.load_dispositions()'s convention), rather than crashing the whole
# report over incidental, optional context
# ---------------------------------------------------------------------------


def test_impact_malformed_trace_matrix_degrades_gracefully():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "trace-matrix.json"), "w") as f:
            f.write("not valid json")
        out = io.StringIO()
        code = run(["impact", "--dir", tmpdir], stdout=out, stderr=io.StringIO())
    assert code == pyfusa.EXIT_OK


def test_impact_malformed_reqs_degrades_gracefully():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
            f.write("not valid json")
        out = io.StringIO()
        code = run(["impact", "--dir", tmpdir], stdout=out, stderr=io.StringIO())
    assert code == pyfusa.EXIT_OK


# ---------------------------------------------------------------------------
# pr add --status -- unvalidated enum silently persisted into
# .fusa-problems.json
# ---------------------------------------------------------------------------


def test_pr_add_invalid_status_is_usage_error():
    # argparse itself prints the "invalid choice" message straight to the
    # real process stderr, not the stderr= passed to run() -- consistent
    # with every other command's argparse-based validation in this file.
    with tempfile.TemporaryDirectory() as tmpdir:
        code = run(
            ["pr", "add", "--dir", tmpdir, "--title", "t", "--status", "BOGUS"],
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
    assert code == pyfusa.EXIT_USAGE


def test_pr_add_valid_status_still_works():
    with tempfile.TemporaryDirectory() as tmpdir:
        code = run(
            ["pr", "add", "--dir", tmpdir, "--title", "t", "--status", "closed"],
            stdout=io.StringIO(),
        )
        assert code == pyfusa.EXIT_OK
        with open(os.path.join(tmpdir, ".fusa-problems.json")) as f:
            doc = json.load(f)
        assert doc["reports"][0]["status"] == "closed"


# ---------------------------------------------------------------------------
# verify --output -- silent success on a non-".json" output path
# ---------------------------------------------------------------------------


def test_verify_output_text_format_prints_confirmation_and_still_saves_evidence():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        run(
            [
                "verify",
                "--dir",
                tmpdir,
                "--output",
                os.path.join(tmpdir, "report.txt"),
                "--format",
                "text",
                "--timeout",
                "5",
            ],
            stdout=out,
        )
        # A prior version printed nothing at all for this exact combination.
        assert "wrote" in out.getvalue()
        assert os.path.exists(os.path.join(tmpdir, "report.txt"))
        # The canonical evidence bundle must still exist -- other rules
        # (VERIFY001/VERIFY002) check for it at this fixed path regardless
        # of where else --output also wrote a copy.
        assert os.path.exists(os.path.join(tmpdir, ".fusa-evidence.json"))


def test_verify_default_output_unchanged():
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        run(["verify", "--dir", tmpdir, "--timeout", "5"], stdout=out)
        assert "wrote .fusa-evidence.json" in out.getvalue()
        assert os.path.exists(os.path.join(tmpdir, ".fusa-evidence.json"))
