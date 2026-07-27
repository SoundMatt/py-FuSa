"""Tests for Features 1-4: HLR/LLR decomposition, tool qualification display,
MC/DC coverage, and V&V independence."""

from __future__ import annotations

import io
import json
import os
import tempfile

import pyfusa
import pyfusa.trace as trace
import pyfusa.qualify as qualify
import pyfusa.coverage as coverage
from pyfusa.cli.main import run
from pyfusa.config import default


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _write_reqs(tmpdir: str, requirements: list) -> None:
    with open(os.path.join(tmpdir, ".fusa-reqs.json"), "w") as f:
        json.dump({"requirements": requirements}, f)


# ===========================================================================
# Feature 1 — HLR/LLR Decomposition
# ===========================================================================


# fusa:test REQ-TRACE001
def test_hlr_llr_no_violations_when_no_llr():
    """If there are only HLRs, no violations are emitted."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_reqs(
            tmpdir,
            [
                {"id": "REQ-001", "title": "HLR 1", "level": "HLR"},
            ],
        )
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        assert matrix.hlr_violations == []
        assert matrix.coverage.hlr_count == 1
        assert matrix.coverage.llr_count == 0


# fusa:test REQ-TRACE001
def test_hlr_llr_valid_hierarchy_no_violations():
    """HLR with a valid LLR child produces no violations."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_reqs(
            tmpdir,
            [
                {"id": "REQ-HLR1", "title": "HLR 1", "level": "HLR"},
                {
                    "id": "REQ-LLR1",
                    "title": "LLR 1",
                    "level": "LLR",
                    "parent_id": "REQ-HLR1",
                },
            ],
        )
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        assert matrix.hlr_violations == []
        assert matrix.coverage.hlr_count == 1
        assert matrix.coverage.llr_count == 1
        assert matrix.coverage.hlr_with_llr == 1


# fusa:test REQ-TRACE001
def test_hlr_llr_orphan_llr_no_parent():
    """LLR with no parent_id generates an orphan-llr violation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_reqs(
            tmpdir,
            [
                {"id": "REQ-HLR1", "title": "HLR 1", "level": "HLR"},
                {"id": "REQ-LLR1", "title": "LLR without parent", "level": "LLR"},
            ],
        )
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        kinds = [v.kind for v in matrix.hlr_violations]
        assert "orphan-llr" in kinds


# fusa:test REQ-TRACE001
def test_hlr_llr_orphan_llr_unknown_parent():
    """LLR referencing a non-existent HLR generates an orphan-llr violation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_reqs(
            tmpdir,
            [
                {"id": "REQ-HLR1", "title": "HLR 1", "level": "HLR"},
                {
                    "id": "REQ-LLR1",
                    "title": "LLR",
                    "level": "LLR",
                    "parent_id": "REQ-DOESNOTEXIST",
                },
            ],
        )
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        kinds = [v.kind for v in matrix.hlr_violations]
        assert "orphan-llr" in kinds


# fusa:test REQ-TRACE001
def test_hlr_llr_empty_hlr_violation():
    """HLR with no LLR children generates an empty-hlr violation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_reqs(
            tmpdir,
            [
                {"id": "REQ-HLR1", "title": "HLR with child", "level": "HLR"},
                {"id": "REQ-HLR2", "title": "HLR without child", "level": "HLR"},
                {
                    "id": "REQ-LLR1",
                    "title": "LLR 1",
                    "level": "LLR",
                    "parent_id": "REQ-HLR1",
                },
            ],
        )
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        kinds = [v.kind for v in matrix.hlr_violations]
        req_ids = [v.req_id for v in matrix.hlr_violations]
        assert "empty-hlr" in kinds
        assert "REQ-HLR2" in req_ids
        # HLR1 has a child so no empty-hlr for it
        assert "REQ-HLR1" not in req_ids


# fusa:test REQ-TRACE001
def test_hlr_llr_findings_are_warnings_without_strict():
    """Without strict level, violations produce WARNING findings."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_reqs(
            tmpdir,
            [
                {"id": "REQ-HLR1", "title": "HLR 1", "level": "HLR"},
                {"id": "REQ-LLR1", "title": "LLR without parent", "level": "LLR"},
            ],
        )
        cfg = default()
        matrix = trace.build(tmpdir, cfg, strict_hlr_llr=False)
        hlr_findings = [f for f in matrix.findings if f.rule_id == "REQ003"]
        assert all(f.severity == pyfusa.SEVERITY_WARNING for f in hlr_findings)


# fusa:test REQ-TRACE001
def test_hlr_llr_findings_are_errors_with_strict():
    """--strict-hlr-llr forces violations to ERROR severity."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_reqs(
            tmpdir,
            [
                {"id": "REQ-HLR1", "title": "HLR 1", "level": "HLR"},
                {"id": "REQ-LLR1", "title": "LLR without parent", "level": "LLR"},
            ],
        )
        cfg = default()
        matrix = trace.build(tmpdir, cfg, strict_hlr_llr=True)
        hlr_findings = [f for f in matrix.findings if f.rule_id == "REQ003"]
        assert len(hlr_findings) > 0
        assert all(f.severity == pyfusa.SEVERITY_ERROR for f in hlr_findings)


# fusa:test REQ-TRACE001
def test_hlr_llr_findings_are_errors_for_asil_d():
    """ASIL-D integrity level forces violations to ERROR severity."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_reqs(
            tmpdir,
            [
                {"id": "REQ-HLR1", "title": "HLR 1", "level": "HLR"},
                {"id": "REQ-LLR1", "title": "LLR without parent", "level": "LLR"},
            ],
        )
        cfg = default()
        cfg.asil = "ASIL-D"
        matrix = trace.build(tmpdir, cfg)
        hlr_findings = [f for f in matrix.findings if f.rule_id == "REQ003"]
        assert all(f.severity == pyfusa.SEVERITY_ERROR for f in hlr_findings)


# fusa:test REQ-TRACE001
def test_hlr_llr_in_json_output():
    """hlrViolations appear in JSON output when violations exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_reqs(
            tmpdir,
            [
                {"id": "REQ-HLR1", "title": "HLR 1", "level": "HLR"},
                {"id": "REQ-LLR1", "title": "LLR without parent", "level": "LLR"},
            ],
        )
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        doc = trace.to_dict(matrix, tmpdir, cfg)
        assert "hlrViolations" in doc
        assert len(doc["hlrViolations"]) > 0
        assert doc["coverage"]["hlrCount"] == 1
        assert doc["coverage"]["llrCount"] == 1


# fusa:test REQ-TRACE001
def test_hlr_llr_coverage_metrics_in_json():
    """Coverage includes hlrCount/llrCount/hlrWithLlr when applicable."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_reqs(
            tmpdir,
            [
                {"id": "REQ-HLR1", "title": "HLR 1", "level": "HLR"},
                {
                    "id": "REQ-LLR1",
                    "title": "LLR 1",
                    "level": "LLR",
                    "parent_id": "REQ-HLR1",
                },
            ],
        )
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        doc = trace.to_dict(matrix, tmpdir, cfg)
        cov = doc["coverage"]
        assert cov["hlrCount"] == 1
        assert cov["llrCount"] == 1
        assert cov["hlrWithLlr"] == 1


# fusa:test REQ-TRACE001
def test_hlr_llr_text_shows_hierarchy():
    """Text renderer shows HLR/LLR hierarchy."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_reqs(
            tmpdir,
            [
                {"id": "REQ-HLR1", "title": "High level", "level": "HLR"},
                {
                    "id": "REQ-LLR1",
                    "title": "Low level",
                    "level": "LLR",
                    "parent_id": "REQ-HLR1",
                },
            ],
        )
        cfg = default()
        matrix = trace.build(tmpdir, cfg)
        text = trace.render_text(matrix)
        assert "REQ-HLR1" in text
        assert "REQ-LLR1" in text
        assert "HLR" in text


# fusa:test REQ-TRACE001
def test_trace_strict_hlr_llr_flag_exits_1():
    """--strict-hlr-llr causes exit 1 when violations exist."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_reqs(
            tmpdir,
            [
                {"id": "REQ-HLR1", "title": "HLR 1", "level": "HLR"},
                {"id": "REQ-LLR1", "title": "LLR without parent", "level": "LLR"},
            ],
        )
        out = io.StringIO()
        err = io.StringIO()
        code = run(
            ["trace", "--dir", tmpdir, "--strict-hlr-llr"], stdout=out, stderr=err
        )
        assert code == pyfusa.EXIT_GATE_FAIL


# fusa:test REQ-TRACE001
def test_trace_strict_hlr_llr_clean_exits_0():
    """--strict-hlr-llr exits 0 when no violations."""
    with tempfile.TemporaryDirectory() as tmpdir:
        _write_reqs(
            tmpdir,
            [
                {"id": "REQ-HLR1", "title": "HLR 1", "level": "HLR"},
                {
                    "id": "REQ-LLR1",
                    "title": "LLR 1",
                    "level": "LLR",
                    "parent_id": "REQ-HLR1",
                },
            ],
        )
        out = io.StringIO()
        err = io.StringIO()
        code = run(
            ["trace", "--dir", tmpdir, "--strict-hlr-llr"], stdout=out, stderr=err
        )
        assert code == pyfusa.EXIT_OK


# ===========================================================================
# Feature 2 — Tool Qualification Display
# ===========================================================================


# fusa:test REQ-QUAL001
def test_qualify_badge_unqualified_by_default():
    """Default qualify run returns unqualified badge."""
    report = qualify.run()
    assert qualify._qualification_badge(report) == qualify.BADGE_UNQUALIFIED


# fusa:test REQ-QUAL001
def test_qualify_badge_self_qualified():
    """qualification_method='self' returns self-qualified badge."""
    report = qualify.run(qualification_method="self")
    assert qualify._qualification_badge(report) == qualify.BADGE_SELF


# fusa:test REQ-QUAL001
def test_qualify_badge_independently_qualified_by_method():
    """qualification_method='independent' returns independently-qualified badge."""
    report = qualify.run(qualification_method="independent")
    assert qualify._qualification_badge(report) == qualify.BADGE_INDEPENDENT


# fusa:test REQ-QUAL001
def test_qualify_badge_independently_qualified_by_identity():
    """qualifier_identity alone is sufficient for independently-qualified badge."""
    report = qualify.run(qualifier_identity="AuditOrg Inc")
    assert qualify._qualification_badge(report) == qualify.BADGE_INDEPENDENT


# fusa:test REQ-QUAL001
def test_qualify_qualification_record_uri_in_report():
    """qualification_record_uri appears in to_dict output."""
    report = qualify.run(
        qualification_method="independent",
        qualification_record_uri="https://example.com/dossier",
        qualifier_identity="AuditOrg",
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        doc = qualify.to_dict(report, tmpdir, cfg)
    assert doc["qualificationRecordUri"] == "https://example.com/dossier"
    assert doc["qualifierIdentity"] == "AuditOrg"
    assert doc["qualificationMethod"] == "independent"


# fusa:test REQ-QUAL001
def test_qualify_badge_in_to_dict():
    """qualificationBadge key is always present in to_dict output."""
    report = qualify.run()
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        doc = qualify.to_dict(report, tmpdir, cfg)
    assert "qualificationBadge" in doc
    assert doc["qualificationBadge"] == qualify.BADGE_UNQUALIFIED


# fusa:test REQ-QUAL001
def test_qualify_cli_qualification_flags_json():
    """CLI --qualification-method and --qualifier flags appear in JSON output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            [
                "qualify",
                "--dir",
                tmpdir,
                "--format",
                "json",
                "--qualification-method",
                "independent",
                "--qualifier",
                "TestOrg",
                "--record-uri",
                "https://dossier.example/q1",
            ],
            stdout=out,
        )
        assert code == pyfusa.EXIT_OK
        doc = json.loads(out.getvalue())
        assert doc["qualificationMethod"] == "independent"
        assert doc["qualifierIdentity"] == "TestOrg"
        assert doc["qualificationRecordUri"] == "https://dossier.example/q1"
        assert doc["qualificationBadge"] == qualify.BADGE_INDEPENDENT


# ===========================================================================
# Feature 3 — MC/DC Coverage
# ===========================================================================


def _write_llvm_coverage(path: str, data: dict) -> None:
    with open(path, "w") as f:
        json.dump(data, f)


# fusa:test REQ-COV001
def test_mcdc_all_conditions_covered():
    """All conditions covered: mcdc.passed = True."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cov_path = os.path.join(tmpdir, "coverage.json")
        _write_llvm_coverage(
            cov_path,
            {
                "data": [
                    {
                        "functions": [
                            {
                                "name": "my_func",
                                "mcdc_records": [
                                    {
                                        "conditions": [
                                            {
                                                "covered_true_count": 5,
                                                "covered_false_count": 3,
                                            },
                                            {
                                                "covered_true_count": 2,
                                                "covered_false_count": 1,
                                            },
                                        ]
                                    }
                                ],
                            }
                        ]
                    }
                ]
            },
        )
        cfg = default()
        doc = coverage.run(tmpdir, cfg, mcdc=True, mcdc_file=cov_path)
        assert "mcdc" in doc
        assert doc["mcdc"]["passed"] is True
        assert doc["mcdc"]["totalConditions"] == 2
        assert doc["mcdc"]["coveredConditions"] == 2
        assert doc["mcdc"]["uncoveredFunctions"] == []


# fusa:test REQ-COV001
def test_mcdc_uncovered_condition_fails():
    """A condition with covered_false_count=0 marks the function as uncovered."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cov_path = os.path.join(tmpdir, "coverage.json")
        _write_llvm_coverage(
            cov_path,
            {
                "data": [
                    {
                        "functions": [
                            {
                                "name": "my_func",
                                "mcdc_records": [
                                    {
                                        "conditions": [
                                            {
                                                "covered_true_count": 5,
                                                "covered_false_count": 0,
                                            },  # not covered
                                        ]
                                    }
                                ],
                            }
                        ]
                    }
                ]
            },
        )
        cfg = default()
        doc = coverage.run(tmpdir, cfg, mcdc=True, mcdc_file=cov_path)
        assert doc["mcdc"]["passed"] is False
        assert "my_func" in doc["mcdc"]["uncoveredFunctions"]
        # Overall report also fails
        assert doc["passed"] is False


# fusa:test REQ-COV001
def test_mcdc_partial_condition_not_covered():
    """covered_true_count=0 (never evaluated true) marks condition uncovered."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cov_path = os.path.join(tmpdir, "coverage.json")
        _write_llvm_coverage(
            cov_path,
            {
                "data": [
                    {
                        "functions": [
                            {
                                "name": "check",
                                "mcdc_records": [
                                    {
                                        "conditions": [
                                            {
                                                "covered_true_count": 0,
                                                "covered_false_count": 3,
                                            },
                                        ]
                                    }
                                ],
                            }
                        ]
                    }
                ]
            },
        )
        cfg = default()
        doc = coverage.run(tmpdir, cfg, mcdc=True, mcdc_file=cov_path)
        assert doc["mcdc"]["coveredConditions"] == 0
        assert doc["mcdc"]["passed"] is False


# fusa:test REQ-COV001
def test_mcdc_missing_file_returns_error():
    """Missing LLVM coverage file results in an error key in mcdc report."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        doc = coverage.run(
            tmpdir, cfg, mcdc=True, mcdc_file=os.path.join(tmpdir, "nonexistent.json")
        )
        assert "mcdc" in doc
        assert "error" in doc["mcdc"]


# fusa:test REQ-COV001
def test_mcdc_json_output_structure():
    """MC/DC JSON output has expected keys."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cov_path = os.path.join(tmpdir, "coverage.json")
        _write_llvm_coverage(
            cov_path,
            {
                "data": [
                    {
                        "functions": [
                            {
                                "name": "f",
                                "mcdc_records": [
                                    {
                                        "conditions": [
                                            {
                                                "covered_true_count": 1,
                                                "covered_false_count": 1,
                                            },
                                        ]
                                    }
                                ],
                            }
                        ]
                    }
                ]
            },
        )
        cfg = default()
        doc = coverage.run(tmpdir, cfg, mcdc=True, mcdc_file=cov_path)
        mc = doc["mcdc"]
        for key in (
            "totalConditions",
            "coveredConditions",
            "coveragePct",
            "threshold",
            "passed",
            "uncoveredFunctions",
            "functions",
        ):
            assert key in mc, f"missing key: {key}"


# fusa:test REQ-COV001
def test_mcdc_threshold_applied():
    """--mcdc-threshold controls the pass/fail gate."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cov_path = os.path.join(tmpdir, "coverage.json")
        _write_llvm_coverage(
            cov_path,
            {
                "data": [
                    {
                        "functions": [
                            {
                                "name": "f",
                                "mcdc_records": [
                                    {
                                        "conditions": [
                                            {
                                                "covered_true_count": 1,
                                                "covered_false_count": 1,
                                            },
                                            # second condition NOT covered
                                            {
                                                "covered_true_count": 0,
                                                "covered_false_count": 1,
                                            },
                                        ]
                                    }
                                ],
                            }
                        ]
                    }
                ]
            },
        )
        cfg = default()
        # At 100% threshold, this fails
        doc_strict = coverage.run(
            tmpdir, cfg, mcdc=True, mcdc_file=cov_path, mcdc_threshold=100.0
        )
        assert doc_strict["mcdc"]["passed"] is False
        # At 40% threshold, 1/2 = 50% passes
        doc_lax = coverage.run(
            tmpdir, cfg, mcdc=True, mcdc_file=cov_path, mcdc_threshold=40.0
        )
        # 50% covered, 1 uncovered function still fails hard gate
        assert doc_lax["mcdc"]["coveragePct"] == 50.0


# fusa:test REQ-COV001
def test_mcdc_cli_flag_json_output():
    """--mcdc flag in CLI produces mcdc key in JSON output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cov_path = os.path.join(tmpdir, "coverage.json")
        _write_llvm_coverage(
            cov_path,
            {
                "data": [
                    {
                        "functions": [
                            {
                                "name": "fn",
                                "mcdc_records": [
                                    {
                                        "conditions": [
                                            {
                                                "covered_true_count": 1,
                                                "covered_false_count": 1,
                                            },
                                        ]
                                    }
                                ],
                            }
                        ]
                    }
                ]
            },
        )
        out = io.StringIO()
        code = run(
            [
                "coverage",
                "--dir",
                tmpdir,
                "--format",
                "json",
                "--mcdc",
                "--mcdc-file",
                cov_path,
            ],
            stdout=out,
        )
        doc = json.loads(out.getvalue())
        assert "mcdc" in doc
        assert doc["mcdc"]["passed"] is True


# fusa:test REQ-COV001
def test_mcdc_without_flag_no_mcdc_key():
    """Without --mcdc flag, the mcdc key is absent from output."""
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        doc = coverage.run(tmpdir, cfg)
        assert "mcdc" not in doc


# ===========================================================================
# Feature 4 — V&V Independence
# ===========================================================================


# fusa:test REQ-QUAL002
def test_vv_independence_unknown_when_no_authors():
    """Independence is 'unknown' when no author or reviewer provided."""
    report = qualify.run()
    assert qualify._independence_status(report) == qualify.INDEPENDENCE_UNKNOWN


# fusa:test REQ-QUAL002
def test_vv_independence_same_author():
    """Independence is 'same-author' when reviewer == author."""
    report = qualify.run(
        implementation_author="Alice",
        independent_reviewer="Alice",
    )
    assert qualify._independence_status(report) == qualify.INDEPENDENCE_SAME_AUTHOR


# fusa:test REQ-QUAL002
def test_vv_independence_independent_when_different():
    """Independence is 'independent' when reviewer differs from author."""
    report = qualify.run(
        implementation_author="Alice",
        independent_reviewer="Bob",
    )
    assert qualify._independence_status(report) == qualify.INDEPENDENCE_INDEPENDENT


# fusa:test REQ-QUAL002
def test_vv_independence_in_to_dict():
    """V&V independence fields appear in to_dict output."""
    report = qualify.run(
        implementation_author="Alice",
        independent_reviewer="Bob",
        independent_test_executor="Carol",
        achievable_asil="ASIL-B",
    )
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        doc = qualify.to_dict(report, tmpdir, cfg)
    assert doc["independenceStatus"] == qualify.INDEPENDENCE_INDEPENDENT
    assert doc["implementationAuthor"] == "Alice"
    assert doc["independentReviewer"] == "Bob"
    assert doc["independentTestExecutor"] == "Carol"
    assert doc["achievableAsil"] == "ASIL-B"


# fusa:test REQ-QUAL002
def test_vv_independence_status_always_in_to_dict():
    """independenceStatus is always present in to_dict output."""
    report = qualify.run()
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        doc = qualify.to_dict(report, tmpdir, cfg)
    assert "independenceStatus" in doc


# fusa:test REQ-QUAL002
def test_vv_independence_cli_flags_json():
    """CLI --implementation-author and --independent-reviewer appear in JSON."""
    with tempfile.TemporaryDirectory() as tmpdir:
        out = io.StringIO()
        code = run(
            [
                "qualify",
                "--dir",
                tmpdir,
                "--format",
                "json",
                "--implementation-author",
                "Alice",
                "--independent-reviewer",
                "Bob",
                "--independent-test-executor",
                "Carol",
                "--achievable-asil",
                "ASIL-C",
            ],
            stdout=out,
        )
        assert code == pyfusa.EXIT_OK
        doc = json.loads(out.getvalue())
        assert doc["independenceStatus"] == qualify.INDEPENDENCE_INDEPENDENT
        assert doc["implementationAuthor"] == "Alice"
        assert doc["independentReviewer"] == "Bob"
        assert doc["independentTestExecutor"] == "Carol"
        assert doc["achievableAsil"] == "ASIL-C"


# fusa:test REQ-QUAL002
def test_vv_unknown_when_only_reviewer():
    """independence is 'unknown' when only reviewer is provided (no author)."""
    report = qualify.run(independent_reviewer="Bob")
    assert qualify._independence_status(report) == qualify.INDEPENDENCE_UNKNOWN


# fusa:test REQ-QUAL002
def test_vv_optional_fields_absent_when_empty():
    """Optional V&V fields are omitted from to_dict when not provided."""
    report = qualify.run()
    with tempfile.TemporaryDirectory() as tmpdir:
        cfg = default()
        doc = qualify.to_dict(report, tmpdir, cfg)
    assert "implementationAuthor" not in doc
    assert "independentReviewer" not in doc
    assert "independentTestExecutor" not in doc
    assert "achievableAsil" not in doc
