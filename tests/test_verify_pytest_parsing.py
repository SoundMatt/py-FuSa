"""Regression tests for a verified counting bug in verify.py, found during
a follow-up authenticity/quality audit: pytest's plain `-q` short-summary
section only ever lists FAILURES/ERRORS, never passes -- a mixed pass/fail
run's per-test loop only ever saw the FAILED line, and because `results`
was then non-empty, the summary-line fallback that would have corrected
the count was skipped too. Verified: summary.passed was silently reported
as 0 for a run that actually had one passing test, and summary.total
undercounted to just the failure count.

Fixed two ways together: pytest is now invoked with -rA (forces a summary
line for every outcome, not just failures), and the aggregate counts are
now always derived from pytest's own summary line (searched per-category,
not by a fixed "passed always comes first" position -- pytest doesn't
guarantee an order) rather than from len(results), so an unexpected
per-test line format can't silently under-report the totals."""

from __future__ import annotations

from pyfusa.verify import _parse_pytest_output


def test_mixed_pass_and_fail_counts_correctly():
    """Exact reproduction of the verified bug: real pytest -q -rA output
    for one passing and one failing test."""
    output = (
        ".F                                                                       [100%]\n"
        "=========================== short test summary info ===========================\n"
        "PASSED test_sample.py::test_ok\n"
        "FAILED test_sample.py::test_bad - assert False\n"
        "1 failed, 1 passed in 0.00s\n"
    )
    result = _parse_pytest_output(output, 1)
    assert result["summary"]["passed"] == 1
    assert result["summary"]["failed"] == 1
    assert result["summary"]["total"] == 2
    statuses = {r["name"]: r["status"] for r in result["results"]}
    assert statuses["test_sample.py::test_ok"] == "pass"
    assert statuses["test_sample.py::test_bad"] == "fail"


def test_all_four_outcomes_in_one_run():
    output = (
        ".FsE                                                                     [100%]\n"
        "=========================== short test summary info ===========================\n"
        "PASSED test_sample.py::test_ok\n"
        "SKIPPED [1] test_sample.py:13: nope\n"
        "ERROR test_sample.py::test_errors - RuntimeError: fixture boom\n"
        "FAILED test_sample.py::test_bad - assert False\n"
        "1 failed, 1 passed, 1 skipped, 1 error in 0.00s\n"
    )
    result = _parse_pytest_output(output, 1)
    s = result["summary"]
    assert (s["passed"], s["failed"], s["errored"], s["skipped"]) == (1, 1, 1, 1)
    assert s["total"] == 4
    assert len(result["results"]) == 4
    assert any(r["status"] == "skip" for r in result["results"])


def test_summary_line_category_order_does_not_matter():
    """pytest doesn't guarantee "passed" appears first in its summary
    line -- "failed" commonly sorts before "passed" -- so counts must not
    depend on a fixed order."""
    failed_first = _parse_pytest_output("1 failed, 3 passed in 0.1s", 1)
    passed_first = _parse_pytest_output("3 passed, 1 failed in 0.1s", 1)
    assert failed_first["summary"]["passed"] == 3
    assert failed_first["summary"]["failed"] == 1
    assert passed_first["summary"] == failed_first["summary"]


def test_all_passing_still_works():
    output = "..                                                                   [100%]\n2 passed in 0.05s\n"
    result = _parse_pytest_output(output, 0)
    assert result["summary"]["passed"] == 2
    assert result["summary"]["total"] == 2
