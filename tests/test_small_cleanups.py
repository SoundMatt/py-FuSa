"""Regression tests for a handful of small findings from a follow-up
authenticity/quality audit of py-FuSa's own code."""

from __future__ import annotations

import os
import tempfile

from pyfusa.config import default


def test_vuln_scan_no_longer_carries_dead_call_graph_field():
    """call_graph was always [] for every finding, written nowhere else and
    read nowhere else -- implying reachability analysis that was never
    actually performed. Removed rather than left as a misleading stub."""
    from pyfusa import vuln

    def fake_query(packages, timeout=30):
        return [{"vulns": [{"id": "OSV-1", "summary": "test"}]}] if packages else []

    orig_installed = vuln._installed_packages
    orig_query = vuln._query_osv
    vuln._installed_packages = lambda: [{"name": "pkg", "version": "1.0"}]
    vuln._query_osv = fake_query
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            doc = vuln.scan(tmpdir, default(project_name="t"), timeout=1)
        assert doc["findings"]
        assert "call_graph" not in doc["findings"][0]
    finally:
        vuln._installed_packages = orig_installed
        vuln._query_osv = orig_query


def test_cyber004_reports_the_real_import_line():
    from pyfusa.rules.cyber import CYBER004

    code = "# c1\n# c2\n\nimport ctypes\n"
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "m.py"), "w") as f:
            f.write(code)
        cfg = default()
        cfg.source_dirs = ["."]
        findings = CYBER004().run(tmpdir, cfg)
    assert len(findings) == 1
    assert findings[0].location.line == 4


def test_cyber017_opener_kwarg_no_longer_matched():
    """opener= is a callable factory, never a permission-bits int -- the
    check on it was dead weight (code that ran would never pass an int
    there). Confirm removing it didn't also remove the real mode= check."""
    from pyfusa.rules.cyber import CYBER017

    code_mode = "open('f', 'w', mode=0o777)\n"
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "m.py"), "w") as f:
            f.write(code_mode)
        cfg = default()
        cfg.source_dirs = ["."]
        findings = CYBER017().run(tmpdir, cfg)
    assert len(findings) == 1


def test_cmd_trace_and_cmd_qualify_have_no_leftover_dead_branches():
    """Two `if ...: pass` no-op branches (leftovers from an incomplete
    refactor) were removed from cli/main.py; confirm the surrounding
    commands still work end to end."""
    import io

    import pyfusa
    from pyfusa.cli.main import run

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, ".fusa.json"), "w") as f:
            f.write('{"project":{"name":"t"}}')
        code = run(["trace", "--dir", tmpdir], stdout=io.StringIO())
        assert code in (pyfusa.EXIT_OK, pyfusa.EXIT_GATE_FAIL)
        code2 = run(["qualify", "--dir", tmpdir], stdout=io.StringIO())
        assert code2 in (pyfusa.EXIT_OK, pyfusa.EXIT_GATE_FAIL)
