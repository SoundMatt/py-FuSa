"""Tests for §4.2 fingerprint algorithm."""

import pyfusa


#fusa:test REQ-FUSA001
def test_fingerprint_format():
    fp = pyfusa.compute_fingerprint("LINT001", "src/foo.py", "function exceeds 60 lines")
    assert fp.startswith("sha256:")
    assert len(fp) == 7 + 64  # "sha256:" + 64 hex chars


#fusa:test REQ-FUSA001
def test_fingerprint_deterministic():
    fp1 = pyfusa.compute_fingerprint("LINT001", "src/foo.py", "function exceeds 60 lines")
    fp2 = pyfusa.compute_fingerprint("LINT001", "src/foo.py", "function exceeds 60 lines")
    assert fp1 == fp2


#fusa:test REQ-FUSA001
def test_fingerprint_digit_normalisation():
    fp1 = pyfusa.compute_fingerprint("LINT001", "src/foo.py", "function is 61 lines")
    fp2 = pyfusa.compute_fingerprint("LINT001", "src/foo.py", "function is 999 lines")
    assert fp1 == fp2, "digit runs should normalise to # before hashing"


#fusa:test REQ-FUSA001
def test_fingerprint_different_rules():
    fp1 = pyfusa.compute_fingerprint("LINT001", "src/foo.py", "test message")
    fp2 = pyfusa.compute_fingerprint("SEC001", "src/foo.py", "test message")
    assert fp1 != fp2


#fusa:test REQ-FUSA001
def test_fingerprint_different_files():
    fp1 = pyfusa.compute_fingerprint("LINT001", "src/a.py", "test message")
    fp2 = pyfusa.compute_fingerprint("LINT001", "src/b.py", "test message")
    assert fp1 != fp2


#fusa:test REQ-FUSA001
def test_normalize_message_collapses_whitespace():
    n = pyfusa.normalize_message("  hello   world  ")
    assert n == "hello world"


#fusa:test REQ-FUSA001
def test_normalize_message_replaces_digits():
    n = pyfusa.normalize_message("file has 123 lines (limit 60)")
    assert n == "file has # lines (limit #)"


#fusa:test REQ-FUSA001
def test_normalize_message_multidigit():
    n = pyfusa.normalize_message("1234 items")
    assert n == "# items"


#fusa:test REQ-FUSA001
def test_normalize_message_no_trailing_space():
    n = pyfusa.normalize_message("hello ")
    assert n == "hello"
