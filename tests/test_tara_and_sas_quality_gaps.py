"""Regression tests for two evidence-quality gaps found during a follow-up
authenticity/quality audit of py-FuSa's own code:

- tara.py's content-quality baseline checked "threat" for a blanket
  fallback pattern but never "mitigations" -- the field a reviewer
  actually acts on.
- sas.py credited "Software Verification Results" as present off mere
  file existence, including a qualify-report.json full of failures, and
  (like the six compliance gap-report generators fixed earlier) treated a
  zero-byte file as real evidence.
"""

from __future__ import annotations

import json
import os
import tempfile

from pyfusa.config import default


def test_tara_flags_identical_mitigations_across_entries():
    from pyfusa import tara

    doc = {
        "threats": [
            {
                "id": f"TARA-{i:03d}",
                "threat": f"threat variant {i}",
                "mitigations": [
                    "identify and implement a specific control for this threat"
                ],
            }
            for i in range(12)
        ]
    }
    findings = tara.quality_findings(doc)
    assert any("mitigations" in f.message for f in findings)


def test_tara_does_not_flag_genuinely_varied_mitigations():
    from pyfusa import tara

    doc = {
        "threats": [
            {"id": f"TARA-{i:03d}", "threat": f"t{i}", "mitigations": [f"control {i}"]}
            for i in range(12)
        ]
    }
    findings = tara.quality_findings(doc)
    assert not any("mitigations" in f.message for f in findings)


def test_sas_zero_byte_qualify_report_is_not_present():
    from pyfusa.sas import generate

    with tempfile.TemporaryDirectory() as tmpdir:
        open(os.path.join(tmpdir, "qualify-report.json"), "w").close()
        doc = generate(tmpdir, default(project_name="t"))
    item = next(c for c in doc["checklist"] if "Verification Results" in c["item"])
    assert item["present"] is False


def test_sas_failing_qualify_report_is_not_present():
    from pyfusa.sas import generate

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "qualify-report.json"), "w") as f:
            json.dump({"total": 10, "passed": 3, "failed": 7}, f)
        doc = generate(tmpdir, default(project_name="t"))
    item = next(c for c in doc["checklist"] if "Verification Results" in c["item"])
    assert item["present"] is False


def test_sas_passing_qualify_report_is_present():
    from pyfusa.sas import generate

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "qualify-report.json"), "w") as f:
            json.dump({"total": 10, "passed": 10, "failed": 0}, f)
        doc = generate(tmpdir, default(project_name="t"))
    item = next(c for c in doc["checklist"] if "Verification Results" in c["item"])
    assert item["present"] is True
    assert item["evidence"] == "qualify-report.json"


def test_sas_falls_back_to_coverage_report_when_qualify_fails():
    """A failing qualify-report.json shouldn't sink the whole item if the
    other candidate (coverage-report.json) is real evidence."""
    from pyfusa.sas import generate

    with tempfile.TemporaryDirectory() as tmpdir:
        with open(os.path.join(tmpdir, "qualify-report.json"), "w") as f:
            json.dump({"total": 10, "passed": 3, "failed": 7}, f)
        with open(os.path.join(tmpdir, "coverage-report.json"), "w") as f:
            json.dump({"kind": "coverage-report", "coveragePct": 92.0}, f)
        doc = generate(tmpdir, default(project_name="t"))
    item = next(c for c in doc["checklist"] if "Verification Results" in c["item"])
    assert item["present"] is True
    assert item["evidence"] == "coverage-report.json"
