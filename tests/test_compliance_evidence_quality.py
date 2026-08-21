"""Tests for pyfusa/compliance/_evidence.py and its adoption across the six
compliance gap-report generators that previously used a bare
os.path.exists() check.

Regression coverage for a verified authenticity gap: a zero-byte or
garbage-content evidence file used to "satisfy" a compliance objective
identically to real evidence, because the only check was file presence."""

from __future__ import annotations

import json
import os
import tempfile
import zipfile

from pyfusa.compliance._evidence import evidence_present
from pyfusa.config import default

# fusa:test REQ-COMPLY002


def test_missing_file_is_absent():
    with tempfile.TemporaryDirectory() as tmpdir:
        assert evidence_present(tmpdir, "nope.json") is False


def test_zero_byte_json_is_absent():
    with tempfile.TemporaryDirectory() as tmpdir:
        open(os.path.join(tmpdir, "empty.json"), "w").close()
        assert evidence_present(tmpdir, "empty.json") is False


def test_garbage_bytes_json_is_absent():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "garbage.json"), "w") as f:
            f.write("this is not json at all, just garbage bytes 12345 !!!")
        assert evidence_present(tmpdir, "garbage.json") is False


def test_empty_json_object_is_absent():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "empty_obj.json"), "w") as f:
            json.dump({}, f)
        assert evidence_present(tmpdir, "empty_obj.json") is False


def test_populated_json_is_present():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "real.json"), "w") as f:
            json.dump({"kind": "some-report", "entries": []}, f)
        assert evidence_present(tmpdir, "real.json") is True


def test_zero_byte_text_file_is_absent():
    with tempfile.TemporaryDirectory() as tmpdir:
        open(os.path.join(tmpdir, "SECURITY.md"), "w").close()
        assert evidence_present(tmpdir, "SECURITY.md") is False


def test_populated_text_file_is_present():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "SECURITY.md"), "w") as f:
            f.write("# Security policy\n\nReport issues to security@example.com\n")
        assert evidence_present(tmpdir, "SECURITY.md") is True


def test_fake_zip_magic_bytes_is_absent():
    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "audit-pack.zip"), "w") as f:
            f.write("PK\x03\x04")  # magic bytes only, not a structurally valid zip
        assert evidence_present(tmpdir, "audit-pack.zip") is False


def test_real_zip_is_present():
    with tempfile.TemporaryDirectory() as tmpdir:
        path = os.path.join(tmpdir, "audit-pack.zip")
        with zipfile.ZipFile(path, "w") as zf:
            zf.writestr("manifest.json", "{}")
        assert evidence_present(tmpdir, "audit-pack.zip") is True


# ---------------------------------------------------------------------------
# End-to-end: every affected compliance module must now report a gap, not
# "satisfied", for garbage-content evidence -- verified per module.
# ---------------------------------------------------------------------------

_MODULES = [
    ("iso26262", {"asil": "ASIL-B"}),
    ("do178", {"dal": "DAL-A"}),
    ("iec61508", {"sil": "SIL-2"}),
    ("iec62443", {}),
    ("iso21434", {}),
    ("unece", {}),
]


def test_zero_byte_evidence_is_a_gap_for_every_affected_module():
    """Matches the original audit reproduction exactly: every evidence file
    created as literally zero bytes must count as a gap, regardless of
    extension (unlike garbage *text* content, a zero-byte file is never
    ambiguous -- there is nothing there for any file type)."""
    import importlib

    for name, kwargs in _MODULES:
        mod = importlib.import_module(f"pyfusa.compliance.{name}")
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = default(project_name="t")
            for obj in mod._OBJECTIVES:
                fname = obj[-1]
                path = os.path.join(tmpdir, fname)
                os.makedirs(os.path.dirname(path) or tmpdir, exist_ok=True)
                open(path, "w").close()
            doc = mod.run(tmpdir, cfg, **kwargs)
            assert doc["summary"]["satisfied"] == 0, (
                f"{name}: a zero-byte file must not count as satisfied "
                f"(got {doc['summary']})"
            )


def test_garbage_json_content_is_a_gap_for_every_affected_module():
    """Garbage bytes in place of real JSON must read as a gap for every
    .json-backed objective (non-JSON evidence like SECURITY.md has a lower,
    presence-only bar by design -- see _evidence.evidence_present)."""
    import importlib

    for name, kwargs in _MODULES:
        mod = importlib.import_module(f"pyfusa.compliance.{name}")
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg = default(project_name="t")
            json_objectives = [o for o in mod._OBJECTIVES if o[-1].endswith(".json")]
            for obj in json_objectives:
                fname = obj[-1]
                path = os.path.join(tmpdir, fname)
                os.makedirs(os.path.dirname(path) or tmpdir, exist_ok=True)
                with open(path, "w") as f:
                    f.write("this is not json at all, just garbage bytes 12345 !!!")
            doc = mod.run(tmpdir, cfg, **kwargs)
            satisfied_ids = {
                o["id"] for o in doc["objectives"] if o["status"] == "satisfied"
            }
            json_ids = {o[0] for o in json_objectives}
            assert not (satisfied_ids & json_ids), (
                f"{name}: garbage JSON must not count as satisfied for "
                f"{satisfied_ids & json_ids}"
            )
