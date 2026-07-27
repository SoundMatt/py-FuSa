"""Tests for qualify command (§6)."""

import pyfusa.qualify as qualify


# fusa:test REQ-FUSA001
def test_qualify_all_pass():
    report = qualify.run()
    assert report.failed == 0, (
        f"qualification failures: {[r.name for r in report.results if r.result != 'PASS']}"
    )


# fusa:test REQ-FUSA001
def test_qualify_total_equals_test_count():
    report = qualify.run()
    assert report.total == len(report.results)


# fusa:test REQ-FUSA001
def test_qualify_passed_plus_failed_le_total():
    report = qualify.run()
    assert report.passed + report.failed <= report.total


# fusa:test REQ-FUSA001
def test_qualify_hash_present():
    report = qualify.run()
    assert report.hash.startswith("sha256:")


# fusa:test REQ-FUSA001
def test_qualify_hash_stable():
    r1 = qualify.run()
    r2 = qualify.run()
    assert r1.hash == r2.hash


# fusa:test REQ-FUSA001
def test_qualify_to_dict_envelope():
    import os
    import tempfile
    from pyfusa.config import default

    report = qualify.run()
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        doc = qualify.to_dict(report, tmpdir, cfg)
    assert doc["schemaVersion"] == pyfusa.SPEC_VERSION
    assert doc["kind"] == "qualification"
    assert "results" in doc
    assert "hash" in doc


# fusa:test REQ-FUSA001
def test_qualify_result_values():
    report = qualify.run()
    valid = {
        qualify.RESULT_PASS,
        qualify.RESULT_FAIL,
        qualify.RESULT_SKIP,
        qualify.RESULT_ERROR,
    }
    for tc in report.results:
        assert tc.result in valid


import pyfusa
