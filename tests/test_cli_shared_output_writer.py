"""Regression tests for a duplicated-logic finding from a follow-up
authenticity/quality audit: the "open --output (or use stdout), write,
close, print a wrote-X confirmation" pattern was hand-copied at ~20 call
sites across cli/main.py with subtle inconsistencies between them (this is
the underlying reason several bugs fixed separately -- badge/req/impact
missing try/except, verify's confirmation gated on the wrong condition --
existed in the first place). All ~16 of the commands where this pattern
was safe to share now go through pyfusa.cli.main._write_output(); the five
spec-governed commands (check/report/trace/qualify/audit-pack, where §2.2
forbids writing *anything* else to stdout when --output is given) either
keep their own bespoke write block or use announce=False.
"""

from __future__ import annotations

import io
import json
import os
import tempfile

import pyfusa
from pyfusa.cli.main import _write_output, run


def test_write_output_to_stdout_when_no_path():
    out = io.StringIO()
    result = _write_output(
        lambda w: w.write("hello\n"), "", "/tmp", out, io.StringIO(), "test"
    )
    assert result is None
    assert out.getvalue() == "hello\n"


def test_write_output_to_file_prints_confirmation():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "out.txt")
        out = io.StringIO()
        result = _write_output(
            lambda w: w.write("hello\n"), path, tmpdir, out, io.StringIO(), "test"
        )
        assert result is None
        assert out.getvalue() == "wrote out.txt\n"
        with open(path) as f:
            assert f.read() == "hello\n"


def test_write_output_announce_false_stays_silent():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "out.txt")
        out = io.StringIO()
        result = _write_output(
            lambda w: w.write("hello\n"),
            path,
            tmpdir,
            out,
            io.StringIO(),
            "test",
            announce=False,
        )
        assert result is None
        assert out.getvalue() == ""


def test_write_output_returns_exit_runtime_on_io_error():
    err = io.StringIO()
    result = _write_output(
        lambda w: w.write("x"),
        "/nonexistent-dir/out.txt",
        "/tmp",
        io.StringIO(),
        err,
        "test",
    )
    assert result == pyfusa.EXIT_RUNTIME
    assert "test:" in err.getvalue()


# ---------------------------------------------------------------------------
# End-to-end: every migrated command still writes correctly, and the five
# spec-governed commands stay completely silent on stdout when --output is
# given (§2.2 MUST -- verified separately per command already in
# test_spec_conformance.py; this just confirms the refactor didn't touch
# their behavior).
# ---------------------------------------------------------------------------


def test_migrated_commands_write_and_confirm():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa.json"), "w") as f:
            f.write('{"project":{"name":"t"}}')
        with open(os.path.join(tmpdir, "mod.py"), "w") as f:
            f.write("def f():\n    pass\n")

        for cmd in ("coupling", "boundary", "fmea", "tara", "vuln", "coverage"):
            out_path = os.path.join(tmpdir, f"{cmd}.json")
            out = io.StringIO()
            run([cmd, "--dir", tmpdir, "--output", out_path], stdout=out, stderr=io.StringIO())
            assert "wrote" in out.getvalue(), cmd
            assert os.path.exists(out_path), cmd


def test_spec_governed_commands_stay_silent_on_output():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa.json"), "w") as f:
            f.write('{"project":{"name":"t"}}')
        for cmd in ("check", "report", "trace", "qualify"):
            out_path = os.path.join(tmpdir, f"{cmd}.json")
            out = io.StringIO()
            run(
                [cmd, "--dir", tmpdir, "--format", "json", "--output", out_path],
                stdout=out,
                stderr=io.StringIO(),
            )
            assert out.getvalue() == "", cmd


def test_gap_report_factory_commands_write_and_confirm():
    """The six do178/iso26262/iec61508/iso21434/iec62443/slsa commands
    share one factory (_cmd_gap_report) -- migrating its single write
    block improves all six at once."""
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa.json"), "w") as f:
            f.write('{"project":{"name":"t"}}')
        for cmd in ("do178", "iso26262", "iec61508", "iso21434", "iec62443", "slsa"):
            out_path = os.path.join(tmpdir, f"{cmd}.json")
            out = io.StringIO()
            run(
                [cmd, "--dir", tmpdir, "--format", "json", "--output", out_path],
                stdout=out,
                stderr=io.StringIO(),
            )
            assert "wrote" in out.getvalue(), cmd
            with open(out_path) as f:
                doc = json.load(f)
            assert doc["kind"] == "gap-report", cmd
