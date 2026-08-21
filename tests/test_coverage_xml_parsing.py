"""Regression tests for coverage.py's coverage.xml parsing, found during a
follow-up authenticity/quality audit: `_read_coverage_xml` was regex-based
(`re.search(r'line-rate="...")` over the raw file text) rather than a real
XML parser -- it had no way to confirm the file was actually well-formed
Cobertura XML, so a file containing only an incidental matching substring
would silently "succeed" with a fabricated coverage percentage."""

from __future__ import annotations

import os
import tempfile

from pyfusa.coverage import _read_coverage_xml


def test_reads_root_line_rate():
    xml = (
        '<?xml version="1.0"?>\n'
        '<coverage line-rate="0.87" branch-rate="0.5">\n'
        "  <packages/>\n"
        "</coverage>\n"
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "coverage.xml")
        with open(path, "w") as f:
            f.write(xml)
        assert _read_coverage_xml(path) == 87.0


def test_garbage_with_spurious_matching_substring_is_rejected():
    """A prior regex-based version would have "succeeded" here with a
    fabricated 99.0% figure -- this isn't XML at all."""
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "coverage.xml")
        with open(path, "w") as f:
            f.write('some log output mentioning line-rate="0.99" in passing')
        assert _read_coverage_xml(path) is None


def test_missing_file_returns_none():
    assert _read_coverage_xml("/nonexistent/coverage.xml") is None


def test_root_without_line_rate_attribute_returns_none():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "coverage.xml")
        with open(path, "w") as f:
            f.write("<coverage><packages/></coverage>")
        assert _read_coverage_xml(path) is None
